# core/cfg_visualizer.py
import r2pipe
import networkx as nx
import plotly.graph_objects as go
from typing import Dict, List, Tuple
import json
import numpy as np
from matplotlib import cm
import plotly.express as px

class CFGVisualizer:
    """3D Control Flow Graph visualization using Plotly"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.r2 = None
        self.graph = None
        self.layout = None
        
    def connect(self):
        """Connect to binary using radare2"""
        self.r2 = r2pipe.open(self.binary_path)
        self.r2.cmd('aaa')
    
    def generate_3d_cfg(self, function_name: str = 'main') -> Dict:
        """Generate 3D visualization of control flow graph"""
        if not self.r2:
            self.connect()
        
        # Find function
        functions = self.r2.cmdj('aflj')
        target_func = next((f for f in functions if f['name'] == function_name), None)
        
        if not target_func:
            return {'error': f'Function {function_name} not found'}
        
        # Get control flow graph
        cfg = self.r2.cmdj(f'agfj @ {target_func["offset"]}')
        
        # Create networkx graph
        G = nx.DiGraph()
        
        # Add nodes with attributes
        for block in cfg:
            offset = block.get('offset', block.get('addr', 0))
            size = block.get('size', 0)
            
            # Try to get instruction count
            instructions = self.r2.cmdj(f'pdbj {size} @ {offset}')
            inst_count = len(instructions) if instructions else 1
            
            G.add_node(offset, 
                      size=size,
                      instructions=inst_count,
                      type=self._determine_block_type(block),
                      label=self._create_block_label(block, instructions))
        
        # Add edges
        for block in cfg:
            offset = block.get('offset', block.get('addr', 0))
            
            # Jump targets
            if 'jump' in block and block['jump'] is not None:
                G.add_edge(offset, block['jump'], type='jump')
            
            # Fall through (next block)
            if 'fail' in block and block['fail'] is not None:
                G.add_edge(offset, block['fail'], type='fallthrough')
        
        # Apply 3D layout
        pos = self._apply_3d_layout(G)
        
        # Create visualization
        viz_data = self._create_plotly_visualization(G, pos)
        
        return {
            'success': True,
            'function': function_name,
            'visualization': viz_data,
            'metrics': self._calculate_metrics(G)
        }
    
    def _determine_block_type(self, block: Dict) -> str:
        """Determine type of basic block"""
        # Look for specific patterns
        if 'fail' in block and 'jump' in block:
            return 'conditional'
        elif 'jump' in block and not 'fail' in block:
            return 'jump'
        elif 'call' in block:
            return 'call'
        elif any(x in str(block).lower() for x in ['ret', 'leave']):
            return 'return'
        else:
            return 'normal'
    
    def _create_block_label(self, block: Dict, instructions: List) -> str:
        """Create informative label for basic block"""
        offset = block.get('offset', block.get('addr', 0))
        label = f"Block 0x{offset:x}"
        
        if instructions and len(instructions) > 0:
            # Show first and last instruction
            first_inst = instructions[0].get('disasm', '')
            last_inst = instructions[-1].get('disasm', '') if len(instructions) > 1 else ''
            
            if first_inst:
                label += f"\n{first_inst}"
            if last_inst and last_inst != first_inst:
                label += f"\n...\n{last_inst}"
        
        return label
    
    def _apply_3d_layout(self, G: nx.DiGraph) -> Dict:
        """Apply 3D force-directed layout to graph"""
        # Use spring layout as base
        pos_2d = nx.spring_layout(G, dim=2, k=1, iterations=50)
        
        # Add Z dimension based on graph hierarchy
        layers = self._calculate_node_layers(G)
        pos_3d = {}
        
        for node, pos in pos_2d.items():
            layer = layers.get(node, 0)
            pos_3d[node] = (pos[0], pos[1], layer * 0.5)
        
        return pos_3d
    
    def _calculate_node_layers(self, G: nx.DiGraph) -> Dict:
        """Calculate hierarchical layers for nodes"""
        layers = {}
        
        # Find entry points (nodes with no predecessors)
        entry_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        # BFS to assign layers
        visited = set()
        queue = [(node, 0) for node in entry_nodes]
        
        while queue:
            node, layer = queue.pop(0)
            if node not in visited:
                visited.add(node)
                layers[node] = layer
                
                for succ in G.successors(node):
                    if succ not in visited:
                        queue.append((succ, layer + 1))
        
        # Assign remaining nodes (in cycles)
        max_layer = max(layers.values()) if layers else 0
        for node in G.nodes():
            if node not in layers:
                layers[node] = max_layer + 1
        
        return layers
    
    def _create_plotly_visualization(self, G: nx.DiGraph, pos: Dict) -> Dict:
        """Create Plotly 3D visualization"""
        # Extract coordinates
        x_nodes = [pos[node][0] for node in G.nodes()]
        y_nodes = [pos[node][1] for node in G.nodes()]
        z_nodes = [pos[node][2] for node in G.nodes()]
        
        # Create edges
        edge_x = []
        edge_y = []
        edge_z = []
        edge_colors = []
        
        for edge in G.edges():
            x0, y0, z0 = pos[edge[0]]
            x1, y1, z1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_z.extend([z0, z1, None])
            
            # Color edges based on type
            edge_type = G.edges[edge].get('type', 'jump')
            if edge_type == 'fallthrough':
                edge_colors.extend(['blue', 'blue', None])
            else:
                edge_colors.extend(['red', 'red', None])
        
        # Create node data
        node_colors = []
        node_sizes = []
        node_labels = []
        node_texts = []
        
        for node in G.nodes():
            # Color based on block type
            block_type = G.nodes[node].get('type', 'normal')
            color_map = {
                'conditional': 'yellow',
                'call': 'green',
                'return': 'orange',
                'jump': 'purple',
                'normal': 'lightblue'
            }
            node_colors.append(color_map.get(block_type, 'gray'))
            
            # Size based on instruction count
            inst_count = G.nodes[node].get('instructions', 1)
            node_sizes.append(20 + min(inst_count * 3, 40))
            
            # Labels and hover text
            node_labels.append(f"0x{node:x}")
            node_texts.append(G.nodes[node].get('label', f"Block at 0x{node:x}"))
        
        # Create Plotly figure
        fig = go.Figure()
        
        # Add edges
        fig.add_trace(go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color=edge_colors, width=2),
            hoverinfo='none',
            name='Control Flow'
        ))
        
        # Add nodes
        fig.add_trace(go.Scatter3d(
            x=x_nodes, y=y_nodes, z=z_nodes,
            mode='markers+text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(color='black', width=1)
            ),
            text=node_labels,
            textposition='top center',
            hovertext=node_texts,
            hoverinfo='text',
            name='Basic Blocks'
        ))
        
        # Update layout
        fig.update_layout(
            title=f"3D Control Flow Graph - Function: {G.graph.get('function', 'Unknown')}",
            scene=dict(
                xaxis=dict(showgrid=False, showticklabels=False, zeroline=False, title=''),
                yaxis=dict(showgrid=False, showticklabels=False, zeroline=False, title=''),
                zaxis=dict(showgrid=False, showticklabels=False, zeroline=False, title='Layer')
            ),
            showlegend=True,
            margin=dict(l=0, r=0, b=0, t=40),
            hovermode='closest'
        )
        
        return fig.to_dict()
    
    def _calculate_metrics(self, G: nx.DiGraph) -> Dict:
        """Calculate graph metrics for complexity analysis"""
        metrics = {
            'nodes': len(G.nodes()),
            'edges': len(G.edges()),
            'cyclomatic_complexity': len(G.edges()) - len(G.nodes()) + 2,
            'average_degree': sum(dict(G.degree()).values()) / len(G.nodes()) if G.nodes() else 0,
            'connected_components': nx.number_weakly_connected_components(G),
            'depth': self._calculate_graph_depth(G),
            'branch_count': len([n for n in G.nodes() if G.out_degree(n) > 1]),
            'leaf_nodes': len([n for n in G.nodes() if G.out_degree(n) == 0])
        }
        
        # Identify loops
        try:
            cycles = list(nx.simple_cycles(G))
            metrics['loops'] = len(cycles)
            metrics['max_loop_size'] = max([len(c) for c in cycles]) if cycles else 0
        except:
            metrics['loops'] = 0
            metrics['max_loop_size'] = 0
        
        return metrics
    
    def _calculate_graph_depth(self, G: nx.DiGraph) -> int:
        """Calculate maximum graph depth"""
        depths = {}
        
        # Find entry nodes
        entry_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not entry_nodes:
            entry_nodes = [min(G.nodes())]  # Use first node if no entry found
        
        # BFS to calculate depths
        queue = [(node, 0) for node in entry_nodes]
        while queue:
            node, depth = queue.pop(0)
            if node not in depths or depth < depths[node]:
                depths[node] = depth
                for succ in G.successors(node):
                    queue.append((succ, depth + 1))
        
        return max(depths.values()) if depths else 0
    
    def export_cfg(self, function_name: str = 'main', format: str = 'html') -> str:
        """Export the 3D CFG visualization"""
        viz_data = self.generate_3d_cfg(function_name)
        
        if not viz_data.get('success'):
            return None
        
        fig = go.Figure(viz_data['visualization'])
        
        if format == 'html':
            return fig.to_html(full_html=True, include_plotlyjs='cdn')
        elif format == 'json':
            return json.dumps(viz_data)
        elif format == 'png':
            fig.write_image("cfg_3d.png")
            return "cfg_3d.png"
        else:
            return None
    
    def close(self):
        """Close radare2 connection"""
        if self.r2:
            self.r2.quit()