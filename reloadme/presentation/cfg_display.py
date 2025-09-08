from __future__ import annotations

from typing import Dict, List, Any, Optional, Set
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import print as rprint


class CFGDisplay:
    """Classe para exibir CFG no terminal usando rich"""
    
    def __init__(self, console: Console):
        self.console = console
    
    def display_cfg_summary(self, cfg_data: Dict[str, Any]) -> None:
        """Exibe resumo geral do CFG"""
        if not cfg_data or cfg_data.get("error"):
            error_msg = cfg_data.get("error", "Erro desconhecido na análise CFG")
            self.console.print(f"[bold red]❌ CFG Analysis Error:[/bold red] {error_msg}")
            return
        
        # Panel com informações básicas
        info_table = Table(show_header=False, box=None, padding=(0, 1))
        info_table.add_column(style="bold cyan")
        info_table.add_column()
        
        info_table.add_row("Architecture:", cfg_data.get("architecture", "Unknown"))
        info_table.add_row("Entry Point:", cfg_data.get("entry_point", "Unknown"))
        info_table.add_row("Functions:", str(len(cfg_data.get("functions", []))))
        info_table.add_row("Basic Blocks:", str(len(cfg_data.get("nodes", []))))
        info_table.add_row("Edges:", str(len(cfg_data.get("edges", []))))
        info_table.add_row("Analysis Type:", cfg_data.get("analysis_type", "unknown"))
        
        panel = Panel(
            info_table,
            title="[bold blue]Control Flow Graph Overview[/bold blue]",
            border_style="blue"
        )
        
        self.console.print(panel)
    
    def display_functions_tree(self, cfg_data: Dict[str, Any]) -> None:
        """Exibe árvore de funções encontradas"""
        functions = cfg_data.get("functions", [])
        if not functions:
            return
        
        tree = Tree("[bold cyan]Functions Discovered[/bold cyan]")
        
        # Separar funções por tipo
        main_funcs = []
        plt_funcs = []
        regular_funcs = []
        
        for func in functions[:20]:  # Limitar para não sobrecarregar
            if any(keyword in func["name"].lower() for keyword in ["main", "_start", "entry"]):
                main_funcs.append(func)
            elif func.get("is_plt", False):
                plt_funcs.append(func)
            else:
                regular_funcs.append(func)
        
        # Adicionar função principal
        if main_funcs:
            main_branch = tree.add("[bold green]Entry/Main Functions[/bold green]")
            for func in main_funcs:
                func_info = f"{func['name']} @ {func['address']} (size: {func['size']}, blocks: {func.get('blocks', 'N/A')})"
                main_branch.add(f"[green]{func_info}[/green]")
        
        # Adicionar funções regulares
        if regular_funcs:
            regular_branch = tree.add("[bold white]Regular Functions[/bold white]")
            for func in regular_funcs[:10]:  # Mostrar apenas as primeiras 10
                func_info = f"{func['name']} @ {func['address']} (size: {func['size']}, blocks: {func.get('blocks', 'N/A')})"
                regular_branch.add(func_info)
            
            if len(regular_funcs) > 10:
                regular_branch.add(f"[dim]... and {len(regular_funcs) - 10} more[/dim]")
        
        # Adicionar funções PLT
        if plt_funcs:
            plt_branch = tree.add("[bold yellow]PLT Functions[/bold yellow]")
            for func in plt_funcs[:5]:  # Mostrar apenas as primeiras 5
                func_info = f"{func['name']} @ {func['address']}"
                plt_branch.add(f"[yellow]{func_info}[/yellow]")
            
            if len(plt_funcs) > 5:
                plt_branch.add(f"[dim]... and {len(plt_funcs) - 5} more PLT functions[/dim]")
        
        panel = Panel(
            tree,
            title="[bold blue]Function Hierarchy[/bold blue]",
            border_style="blue"
        )
        
        self.console.print(panel)
    
    def display_cfg_graph_ascii(self, cfg_data: Dict[str, Any], target_function: Optional[str] = None) -> None:
        """Exibe representação ASCII do CFG"""
        nodes = cfg_data.get("nodes", [])
        edges = cfg_data.get("edges", [])
        
        if not nodes:
            return
        
        # Filtrar por função se especificada
        if target_function:
            nodes = [n for n in nodes if n.get("function") == target_function]
            node_addrs = {n["address"] for n in nodes}
            edges = [e for e in edges if e["from"] in node_addrs and e["to"] in node_addrs]
        
        # Criar gráfico ASCII com fluxo visual
        title = f"Control Flow Graph"
        if target_function:
            title += f" - Function: {target_function}"
        
        # Se há edges, criar visualização com fluxo
        if edges:
            self._display_flow_diagram(nodes, edges, target_function)
        else:
            self._display_simple_blocks(nodes, target_function)
    
    def display_basic_blocks_table(self, cfg_data: Dict[str, Any], limit: int = 10) -> None:
        """Exibe tabela de basic blocks"""
        nodes = cfg_data.get("nodes", [])
        if not nodes:
            return
        
        table = Table(title="Basic Blocks Details")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Function", style="green")
        table.add_column("Size", justify="right", style="yellow")
        table.add_column("Instructions", justify="right", style="magenta")
        table.add_column("Connections", style="white")
        
        edges = cfg_data.get("edges", [])
        
        for node in nodes[:limit]:
            addr = node["address"]
            func_name = node.get("function", "unknown")
            size = str(node.get("size", 0))
            instructions = str(node.get("instructions", 0))
            
            # Contar conexões
            outgoing = len([e for e in edges if e["from"] == addr])
            incoming = len([e for e in edges if e["to"] == addr])
            connections = f"Out: {outgoing} | In: {incoming}"
            
            table.add_row(addr, func_name, size, instructions, connections)
        
        if len(nodes) > limit:
            table.add_row("...", f"[dim]+{len(nodes) - limit} more blocks[/dim]", "", "", "")
        
        self.console.print(table)
    
    def display_cfg_statistics(self, cfg_data: Dict[str, Any]) -> None:
        """Exibe estatísticas detalhadas do CFG"""
        functions = cfg_data.get("functions", [])
        nodes = cfg_data.get("nodes", [])
        edges = cfg_data.get("edges", [])
        
        if not any([functions, nodes, edges]):
            return
        
        # Calcular estatísticas
        total_functions = len(functions)
        total_blocks = len(nodes)
        total_edges = len(edges)
        
        # Estatísticas de funções
        func_sizes = [f.get("size", 0) for f in functions if f.get("size", 0) > 0]
        avg_func_size = sum(func_sizes) / len(func_sizes) if func_sizes else 0
        
        # Estatísticas de basic blocks
        block_sizes = [n.get("size", 0) for n in nodes if n.get("size", 0) > 0]
        avg_block_size = sum(block_sizes) / len(block_sizes) if block_sizes else 0
        
        # Criar tabela de estatísticas
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column(style="bold cyan")
        stats_table.add_column(justify="right")
        
        stats_table.add_row("Total Functions:", str(total_functions))
        stats_table.add_row("Total Basic Blocks:", str(total_blocks))
        stats_table.add_row("Total Edges:", str(total_edges))
        stats_table.add_row("Avg Function Size:", f"{avg_func_size:.1f} bytes")
        stats_table.add_row("Avg Block Size:", f"{avg_block_size:.1f} bytes")
        
        if total_blocks > 0:
            complexity = total_edges / total_blocks
            stats_table.add_row("Complexity Ratio:", f"{complexity:.2f}")
        
        panel = Panel(
            stats_table,
            title="[bold blue]CFG Statistics[/bold blue]",
            border_style="blue"
        )
        
        self.console.print(panel)
    
    def display_full_cfg_analysis(self, cfg_data: Dict[str, Any], show_details: bool = True) -> None:
        """Exibe análise completa do CFG"""
        self.display_cfg_summary(cfg_data)
        self.console.print()
        
        if show_details and not cfg_data.get("error"):
            self.display_functions_tree(cfg_data)
            self.console.print()
            
            self.display_cfg_graph_ascii(cfg_data)
            self.console.print()
            
            self.display_basic_blocks_table(cfg_data, limit=15)
            self.console.print()
            
            self.display_cfg_statistics(cfg_data)
    
    def _get_function_color(self, func_name: str) -> str:
        """Retorna cor baseada no nome da função"""
        colors = {
            "main": "bright_blue",
            "_start": "bright_green",
            "entry": "bright_green",
            "plt": "yellow",
            "sub_": "white",
        }
        
        func_lower = func_name.lower()
        for key, color in colors.items():
            if key in func_lower:
                return color
        
        return "white"
    
    def _display_flow_diagram(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], target_function: Optional[str] = None) -> None:
        """Exibe diagrama de fluxo com conexões visuais"""
        title = f"Control Flow Graph"
        if target_function:
            title += f" - Function: {target_function}"
            
        # Construir mapa de conexões
        connections = {}
        for edge in edges:
            from_addr = edge["from"]
            to_addr = edge["to"]
            if from_addr not in connections:
                connections[from_addr] = []
            connections[from_addr].append(to_addr)
        
        # Ordenar nós por endereço para fluxo lógico
        sorted_nodes = sorted(nodes, key=lambda n: int(n["address"], 16))
        
        # Construir representação visual
        flow_lines = []
        flow_lines.append(f"[bold cyan]{title}[/bold cyan]")
        flow_lines.append("")
        
        for i, node in enumerate(sorted_nodes[:10]):  # Limitar a 10 para legibilidade
            addr = node["address"]
            size = node.get("size", 0)
            instructions = node.get("instructions", 0)
            
            # Linha do bloco
            block_line = f"[yellow]+- {addr}[/yellow] [white](size: {size}, instr: {instructions})[/white]"
            flow_lines.append(block_line)
            
            # Conexões saindo deste bloco
            if addr in connections:
                targets = connections[addr]
                for j, target in enumerate(targets):
                    if j == len(targets) - 1:  # Última conexão
                        flow_lines.append(f"[green]  +-> {target}[/green]")
                    else:
                        flow_lines.append(f"[green]  +-> {target}[/green]")
            else:
                flow_lines.append("[red]  +-- (no outgoing connections)[/red]")
            
            # Espaçamento entre blocos
            if i < len(sorted_nodes) - 1:
                flow_lines.append("[dim]  |[/dim]")
        
        if len(sorted_nodes) > 10:
            flow_lines.append(f"[dim]... and {len(sorted_nodes) - 10} more blocks[/dim]")
        
        # Criar painel com o fluxo
        flow_content = "\n".join(flow_lines)
        panel = Panel(
            flow_content,
            title="[bold blue]Control Flow Visualization[/bold blue]",
            border_style="blue"
        )
        
        self.console.print(panel)
        
        # Mostrar estatísticas de conexões
        self._display_connection_stats(edges)
    
    def _display_simple_blocks(self, nodes: List[Dict[str, Any]], target_function: Optional[str] = None) -> None:
        """Exibe blocos simples quando não há edges"""
        title = f"Control Flow Graph"
        if target_function:
            title += f" - Function: {target_function}"
            
        cfg_tree = Tree(f"[bold cyan]{title}[/bold cyan]")
        
        # Organizar nós por função
        functions_nodes = {}
        for node in nodes[:15]:  # Limitar para não sobrecarregar
            func_name = node.get("function", "unknown")
            if func_name not in functions_nodes:
                functions_nodes[func_name] = []
            functions_nodes[func_name].append(node)
        
        # Construir árvore por função
        for func_name, func_nodes in functions_nodes.items():
            func_color = self._get_function_color(func_name)
            func_branch = cfg_tree.add(f"[{func_color}]{func_name}[/{func_color}]")
            
            # Adicionar basic blocks
            for node in func_nodes:
                addr = node["address"]
                size = node.get("size", 0)
                instructions = node.get("instructions", 0)
                
                node_info = f"{addr} (size: {size}, instr: {instructions})"
                func_branch.add(f"[white]{node_info}[/white]")
        
        if len(nodes) > 15:
            cfg_tree.add(f"[dim]... and {len(nodes) - 15} more basic blocks[/dim]")
        
        panel = Panel(
            cfg_tree,
            title="[bold blue]Control Flow Visualization[/bold blue]",
            border_style="blue"
        )
        
        self.console.print(panel)
    
    def _display_connection_stats(self, edges: List[Dict[str, Any]]) -> None:
        """Exibe estatísticas das conexões"""
        if not edges:
            return
            
        # Contar tipos de conexões
        connection_count = len(edges)
        
        # Encontrar nós com mais conexões
        outgoing_counts = {}
        incoming_counts = {}
        
        for edge in edges:
            from_addr = edge["from"]
            to_addr = edge["to"]
            
            outgoing_counts[from_addr] = outgoing_counts.get(from_addr, 0) + 1
            incoming_counts[to_addr] = incoming_counts.get(to_addr, 0) + 1
        
        # Estatísticas básicas
        stats_lines = []
        stats_lines.append(f"[cyan]Total Connections:[/cyan] {connection_count}")
        
        if outgoing_counts:
            max_out = max(outgoing_counts.values())
            max_out_addr = [addr for addr, count in outgoing_counts.items() if count == max_out][0]
            stats_lines.append(f"[yellow]Most Outgoing:[/yellow] {max_out_addr} ({max_out} connections)")
        
        if incoming_counts:
            max_in = max(incoming_counts.values())
            max_in_addr = [addr for addr, count in incoming_counts.items() if count == max_in][0]
            stats_lines.append(f"[green]Most Incoming:[/green] {max_in_addr} ({max_in} connections)")
        
        stats_content = "\n".join(stats_lines)
        
        stats_panel = Panel(
            stats_content,
            title="[bold magenta]Connection Statistics[/bold magenta]",
            border_style="magenta"
        )
        
        self.console.print(stats_panel)