from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False


@dataclass
class CFGAnalyzer:
    filepath: str
    angr_available: bool = ANGR_AVAILABLE
    graphviz_available: bool = GRAPHVIZ_AVAILABLE
    cfg_data: Dict[str, Any] = field(default_factory=dict)
    
    def generate_cfg(self, function_addr: Optional[int] = None, function_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Gera um CFG usando angr para o binário especificado.
        
        Args:
            function_addr: Endereço específico de uma função para analisar
            function_name: Nome da função para analisar (ex: 'main')
            
        Returns:
            Dicionário contendo dados do CFG e metadados
        """
        if not self.angr_available:
            return {
                "error": "angr não está disponível. Instale com: pip install angr",
                "nodes": [],
                "edges": [],
                "functions": []
            }
            
        if not os.path.exists(self.filepath):
            return {
                "error": f"Arquivo não encontrado: {self.filepath}",
                "nodes": [],
                "edges": [],
                "functions": []
            }
            
        try:
            # Carregar o binário
            project = angr.Project(self.filepath, auto_load_libs=False)
            
            # Gerar CFG
            cfg = project.analyses.CFGFast()
            
            result = {
                "binary_path": self.filepath,
                "architecture": project.arch.name,
                "entry_point": hex(project.entry),
                "nodes": [],
                "edges": [],
                "functions": [],
                "basic_blocks": [],
                "error": None
            }
            
            # Se uma função específica foi solicitada
            target_function = None
            if function_name:
                # Buscar função por nome
                for func_addr, func in cfg.functions.items():
                    if func.name == function_name or function_name in func.name:
                        target_function = func
                        break
            elif function_addr:
                # Buscar função por endereço
                target_function = cfg.functions.get(function_addr)
                
            if target_function:
                result.update(self._analyze_single_function(cfg, target_function))
            else:
                result.update(self._analyze_full_cfg(cfg))
                
            # Extrair edges globalmente do CFG usando método mais robusto
            result["edges"] = self._extract_edges_from_cfg(cfg, result.get("nodes", []))
                
            self.cfg_data = result
            return result
            
        except Exception as e:
            logging.error(f"Erro ao gerar CFG: {e}")
            return {
                "error": f"Erro ao gerar CFG: {str(e)}",
                "nodes": [],
                "edges": [],
                "functions": []
            }
    
    def _analyze_single_function(self, cfg, function) -> Dict[str, Any]:
        """Analisa uma função específica"""
        nodes = []
        edges = []
        basic_blocks = []
        
        # Coletar nós (basic blocks) da função
        for block_addr in function.block_addrs:
            try:
                block = function.get_node(block_addr)
                if block:
                    # Calcular número de instruções baseado no tamanho (aproximação)
                    estimated_instructions = max(1, block.size // 4) if block.size > 0 else 1
                    
                    nodes.append({
                        "id": hex(block.addr),
                        "address": hex(block.addr),
                        "size": block.size,
                        "instructions": estimated_instructions,
                        "function": function.name
                    })
                    
                    # Informações do basic block
                    basic_blocks.append({
                        "address": hex(block.addr),
                        "size": block.size,
                        "instructions": estimated_instructions,
                        "function": function.name
                    })
                    
                    # Coletar edges (conexões entre blocos) - método mais robusto
                    try:
                        # Tentar diferentes métodos para obter sucessores
                        successors = []
                        
                        # Método 1: Usando transitions do CFG
                        try:
                            for addr in cfg.graph.successors(block):
                                successors.append(addr)
                        except:
                            pass
                        
                        # Método 2: Usando block.successors se disponível
                        if not successors:
                            try:
                                for succ in block.successors:
                                    successors.append(succ)
                            except:
                                pass
                        
                        # Adicionar edges encontrados
                        for successor in successors:
                            try:
                                succ_addr = getattr(successor, 'addr', successor)
                                if isinstance(succ_addr, int):
                                    edges.append({
                                        "from": hex(block.addr),
                                        "to": hex(succ_addr),
                                        "type": "jump"
                                    })
                            except:
                                continue
                                
                    except Exception as e:
                        logging.debug(f"Erro ao processar sucessores do bloco {hex(block.addr)}: {e}")
            except Exception as e:
                logging.warning(f"Erro ao processar bloco {hex(block_addr)}: {e}")
                continue
        
        return {
            "analysis_type": "single_function",
            "target_function": {
                "name": function.name,
                "address": hex(function.addr),
                "size": function.size,
                "blocks_count": len(nodes)
            },
            "nodes": nodes,
            "edges": edges,
            "basic_blocks": basic_blocks,
            "functions": [{
                "name": function.name,
                "address": hex(function.addr),
                "size": function.size,
                "blocks": len(nodes)
            }]
        }
    
    def _analyze_full_cfg(self, cfg) -> Dict[str, Any]:
        """Analisa o CFG completo do binário"""
        nodes = []
        edges = []
        functions = []
        basic_blocks = []
        
        # Coletar informações das funções
        for func_addr, function in cfg.functions.items():
            functions.append({
                "name": function.name,
                "address": hex(func_addr),
                "size": function.size,
                "blocks": len(function.block_addrs),
                "is_plt": function.is_plt,
                "is_syscall": function.is_syscall
            })
            
            # Coletar nós (basic blocks) de cada função
            for block_addr in function.block_addrs:
                try:
                    block = function.get_node(block_addr)
                    if block:
                        # Calcular número de instruções baseado no tamanho (aproximação)
                        estimated_instructions = max(1, block.size // 4) if block.size > 0 else 1
                        
                        nodes.append({
                            "id": hex(block.addr),
                            "address": hex(block.addr),
                            "size": block.size,
                            "instructions": estimated_instructions,
                            "function": function.name
                        })
                        
                        basic_blocks.append({
                            "address": hex(block.addr),
                            "size": block.size,
                            "instructions": estimated_instructions,
                            "function": function.name
                        })
                        
                        # Coletar edges
                        try:
                            successors = list(block.successors)
                            for successor in successors:
                                edges.append({
                                    "from": hex(block.addr),
                                    "to": hex(successor.addr),
                                    "type": "jump"
                                })
                        except (TypeError, AttributeError) as e:
                            # Log mais específico para debugging
                            logging.debug(f"Erro ao processar sucessores do bloco {hex(block.addr)}: {e}")
                except Exception as e:
                    logging.warning(f"Erro ao processar bloco {hex(block_addr)}: {e}")
                    continue
        
        return {
            "analysis_type": "full_binary",
            "nodes": nodes,
            "edges": edges,
            "basic_blocks": basic_blocks,
            "functions": functions
        }
    
    def _extract_edges_from_cfg(self, cfg, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extrai conexões do CFG usando métodos mais robustos"""
        edges = []
        node_addrs = {node["address"] for node in nodes}
        
        try:
            # Método 1: Usar o grafo networkx interno do CFG
            if hasattr(cfg, 'graph'):
                for source, target in cfg.graph.edges():
                    try:
                        source_addr = hex(getattr(source, 'addr', source))
                        target_addr = hex(getattr(target, 'addr', target))
                        
                        # Só incluir se ambos os nós existem na nossa lista
                        if source_addr in node_addrs and target_addr in node_addrs:
                            edges.append({
                                "from": source_addr,
                                "to": target_addr,
                                "type": "jump"
                            })
                    except:
                        continue
            
            # Método 2: Usar transições por função se o método 1 falhar
            if not edges:
                for func_addr, function in cfg.functions.items():
                    try:
                        for block_addr in function.block_addrs:
                            block = function.get_node(block_addr)
                            if block:
                                source_addr = hex(block.addr)
                                if source_addr in node_addrs:
                                    # Tentar obter sucessores
                                    try:
                                        for succ in cfg.graph.successors(block):
                                            succ_addr = hex(getattr(succ, 'addr', succ))
                                            if succ_addr in node_addrs:
                                                edges.append({
                                                    "from": source_addr,
                                                    "to": succ_addr,
                                                    "type": "jump"
                                                })
                                    except:
                                        continue
                    except:
                        continue
                        
        except Exception as e:
            logging.debug(f"Erro ao extrair edges: {e}")
        
        return edges
    
    def generate_dot_graph(self, cfg_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Gera uma representação DOT do CFG para visualização
        
        Args:
            cfg_data: Dados do CFG (usa self.cfg_data se não fornecido)
            
        Returns:
            String no formato DOT
        """
        if cfg_data is None:
            cfg_data = self.cfg_data
            
        if not cfg_data or "nodes" not in cfg_data:
            return "digraph CFG { error [label=\"Nenhum dado de CFG disponível\"]; }"
            
        dot_lines = ["digraph CFG {"]
        dot_lines.append("  rankdir=TB;")
        dot_lines.append("  node [shape=box, style=filled];")
        
        # Adicionar nós
        for node in cfg_data.get("nodes", []):
            addr = node.get("address", "")
            func_name = node.get("function", "unknown")
            size = node.get("size", 0)
            instructions = node.get("instructions", 0)
            
            # Cor baseada na função
            color = self._get_function_color(func_name)
            
            label = f"{addr}\\n{func_name}\\nSize: {size}\\nInstr: {instructions}"
            dot_lines.append(f'  "{addr}" [label="{label}", fillcolor="{color}"];')
        
        # Adicionar edges
        for edge in cfg_data.get("edges", []):
            from_addr = edge.get("from", "")
            to_addr = edge.get("to", "")
            edge_type = edge.get("type", "jump")
            
            color = "red" if edge_type == "call" else "black"
            dot_lines.append(f'  "{from_addr}" -> "{to_addr}" [color="{color}"];')
        
        dot_lines.append("}")
        return "\n".join(dot_lines)
    
    def _get_function_color(self, func_name: str) -> str:
        """Retorna uma cor baseada no nome da função"""
        colors = {
            "main": "lightblue",
            "entry": "lightgreen",
            "_start": "lightgreen",
            "plt": "lightyellow",
            "unknown": "lightgray"
        }
        
        for key, color in colors.items():
            if key in func_name.lower():
                return color
                
        # Hash simples para cores consistentes
        hash_val = hash(func_name) % 6
        color_list = ["lightcoral", "lightpink", "lightsalmon", "lightsteelblue", "lightcyan", "lightgoldenrodyellow"]
        return color_list[hash_val]
    
    def render_cfg_to_file(self, output_path: str, format: str = "png", cfg_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Renderiza o CFG para um arquivo usando graphviz
        
        Args:
            output_path: Caminho do arquivo de saída (sem extensão)
            format: Formato do arquivo (png, pdf, svg, etc.)
            cfg_data: Dados do CFG (usa self.cfg_data se não fornecido)
            
        Returns:
            True se sucesso, False caso contrário
        """
        if not self.graphviz_available:
            logging.error("graphviz não está disponível. Instale com: pip install graphviz")
            return False
            
        try:
            dot_content = self.generate_dot_graph(cfg_data)
            
            # Criar o grafo
            graph = graphviz.Source(dot_content)
            
            # Renderizar
            graph.render(output_path, format=format, cleanup=True)
            
            logging.info(f"CFG renderizado em: {output_path}.{format}")
            return True
            
        except Exception as e:
            logging.error(f"Erro ao renderizar CFG: {e}")
            return False
    
    def save_cfg_json(self, output_path: str, cfg_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Salva os dados do CFG em formato JSON
        
        Args:
            output_path: Caminho do arquivo JSON de saída
            cfg_data: Dados do CFG (usa self.cfg_data se não fornecido)
            
        Returns:
            True se sucesso, False caso contrário
        """
        if cfg_data is None:
            cfg_data = self.cfg_data
            
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(cfg_data, f, indent=2, ensure_ascii=False)
                
            logging.info(f"Dados do CFG salvos em: {output_path}")
            return True
            
        except Exception as e:
            logging.error(f"Erro ao salvar CFG JSON: {e}")
            return False
    
    def get_function_list(self) -> List[Dict[str, Any]]:
        """Retorna lista de funções encontradas no CFG"""
        if not self.cfg_data:
            return []
        return self.cfg_data.get("functions", [])
    
    def get_basic_blocks_for_function(self, function_name: str) -> List[Dict[str, Any]]:
        """Retorna basic blocks de uma função específica"""
        if not self.cfg_data:
            return []
            
        blocks = []
        for block in self.cfg_data.get("basic_blocks", []):
            if block.get("function") == function_name:
                blocks.append(block)
                
        return blocks