## Relatório de Refatoração Inicial do Core

Esta etapa focou em mover os primeiros componentes chave do antigo diretório `core/` para a nova estrutura modular em `src/`, e realizar um melhor esforço para ajustar as importações.

### 1. Arquivos Movidos e Novos Caminhos

Os seguintes arquivos foram movidos com sucesso:

*   `core/analyzer.py` -> `src/modules/static_analysis/static_analyzer.py`
*   `core/dynamic_analyzer.py` -> `src/modules/dynamic_analysis/dynamic_analyzer.py`
*   `core/exploit_gen.py` -> `src/modules/exploit_development/exploit_generator.py`
*   `core/rop_generator.py` -> `src/modules/exploit_development/rop_generator.py`
*   `core/bof_solver.py` -> `src/modules/exploit_development/bof_solver.py`
*   `core/utils.py` -> `src/common/utils.py`

### 2. Criação de Diretórios e `__init__.py`

Os seguintes diretórios e arquivos `__init__.py` foram criados para suportar a nova estrutura de pacotes:

*   `src/__init__.py`
*   `src/common/__init__.py`
*   `src/modules/__init__.py`
*   `src/modules/static_analysis/__init__.py`
*   `src/modules/dynamic_analysis/__init__.py`
*   `src/modules/exploit_development/__init__.py`

### 3. Resumo dos Ajustes de Importação Realizados

As importações foram atualizadas nos seguintes arquivos para refletir os novos caminhos:

*   **`src/modules/static_analysis/static_analyzer.py`**:
    *   `from utils.logging import get_logger` -> `from src.common.logging import get_logger`
    *   `from utils.constants import SAFE_TIMEOUT` -> `from src.common.constants import SAFE_TIMEOUT`
*   **`src/modules/exploit_development/bof_solver.py`**:
    *   `from reloadai.utils.logging import get_logger` -> `from src.common.logging import get_logger`
    *   `from reloadai.utils.constants import SAFE_TIMEOUT` -> `from src.common.constants import SAFE_TIMEOUT`
*   **`cli/reloadai_cli.py`**:
    *   `from utils.sanitizer import BinarySanitizer` -> `from src.common.sanitizer import BinarySanitizer`
    *   `from utils.interpreter import get_interp` -> `from src.common.interpreter import get_interp`
    *   `from core.analyzer import BinaryAnalyzer` -> `from src.modules.static_analysis.static_analyzer import BinaryAnalyzer`
    *   `from core.dynamic import DynamicAnalyzer` -> `from src.modules.dynamic_analysis.dynamic_analyzer import DynamicAnalyzer` (também corrigido o nome do módulo de `core.dynamic` para `core.dynamic_analyzer` no caminho de origem da busca)
    *   `from core.exploit_gen import ExploitGenerator` -> `from src.modules.exploit_development.exploit_generator import ExploitGenerator`
    *   `from core.bof_solver import BOFSolver` -> `from src.modules.exploit_development.bof_solver import BOFSolver`
*   **`main.py`**:
    *   `from core.analyzer import BinaryAnalyzer` -> `from src.modules.static_analysis.static_analyzer import BinaryAnalyzer`
    *   `from core.exploit_gen import ExploitGenerator` -> `from src.modules.exploit_development.exploit_generator import ExploitGenerator`
    *   `from core.dynamic_analyzer import DynamicAnalyzer` -> `from src.modules.dynamic_analysis.dynamic_analyzer import DynamicAnalyzer`
*   **`core/__init__.py`**:
    *   `from .analyzer import BinaryAnalyzer, BinaryAnalysisError, SecurityError` -> `from src.modules.static_analysis.static_analyzer import BinaryAnalyzer, BinaryAnalysisError, SecurityError`
    *   `from .dynamic import DynamicAnalyzer` -> `from src.modules.dynamic_analysis.dynamic_analyzer import DynamicAnalyzer`
    *   `from .exploit_gen import ExploitGenerator` -> `from src.modules.exploit_development.exploit_generator import ExploitGenerator`
    *   `from .bof_solver import BoFSolver` -> `from src.modules.exploit_development.bof_solver import BoFSolver`
*   **`core/bof_pipeline.py`**:
    *   `from .rop_generator import find_gadgets` -> `from src.modules.exploit_development.rop_generator import find_gadgets`
*   **`core/dinamic.py`**:
    *   `from utils.logging import get_logger` -> `from src.common.logging import get_logger`
*   **`core/tasks.py`**:
    *   `from .utils import logger, get_file_format` -> `from src.common.utils import logger, get_file_format`

### 4. Problemas de Importação Não Resolvidos / Falhas

*   **`reloadai.py`**:
    *   Falha persistente ao tentar atualizar as importações usando a ferramenta `replace_with_git_merge_diff`. O bloco `SEARCH` não foi encontrado repetidamente, mesmo após tentativas de cópia verbatim e simplificação da alteração.
    *   As importações que precisam ser alteradas neste arquivo são:
        *   `from utils.sanitizer import BinarySanitizer` -> `from src.common.sanitizer import BinarySanitizer`
        *   `from utils.interpreter import get_interp` -> `from src.common.interpreter import get_interp`
    *   Esta falha precisará ser investigada, possivelmente devido a caracteres invisíveis, sensibilidade da ferramenta de diff, ou uma necessidade de abordagem manual/diferente para este arquivo específico.

### 5. Observações Iniciais e Áreas para Refatoração Futura

*   **Classe `BinaryAnalyzer` Ausente/Mal Localizada**:
    *   Os arquivos `cli/reloadai_cli.py`, `main.py`, e `core/__init__.py` importavam `BinaryAnalyzer` (e `BinaryAnalysisError`, `SecurityError` em `core/__init__.py`) de `core.analyzer`.
    *   O arquivo `core/analyzer.py` que foi movido para `src/modules/static_analysis/static_analyzer.py` contém apenas a função `analyze_static` e não define a classe `BinaryAnalyzer`.
    *   A classe `BinaryAnalyzer` parece estar definida em `core/tasks.py`.
    *   **Ação Futura Necessária**: As importações que agora apontam para `src.modules.static_analysis.static_analyzer` esperando por `BinaryAnalyzer` (e classes relacionadas) irão falhar. Será preciso:
        1.  Decidir a localização correta da classe `BinaryAnalyzer`. Se for em `core/tasks.py`, as importações precisam ser ajustadas para `from core.tasks import BinaryAnalyzer`.
        2.  Se a intenção é que `static_analyzer.py` contenha essa classe, então o código da classe precisa ser movido para lá.
        3.  Harmonizar o uso de `BinaryAnalyzer` e `analyze_static`.

*   **Dependência de `utils/*` em `src/common/`**:
    *   Muitas das correções de importação (ex: `utils.logging`, `utils.constants`, `utils.sanitizer`) foram feitas assumindo que os arquivos do diretório `utils/` de nível superior serão movidos para `src/common/`.
    *   Atualmente, apenas `core/utils.py` foi movido para `src/common/utils.py`.
    *   **Ação Futura Necessária**: Para que estas importações funcionem, os respectivos arquivos (`logging.py`, `constants.py`, `sanitizer.py`, `interpreter.py`) do diretório `utils/` devem ser movidos para `src/common/`.

*   **Conteúdo de `src/common/utils.py`**:
    *   O arquivo `src/common/utils.py` (anteriormente `core/utils.py`) contém atualmente apenas duas funções simples (`logger` e `get_file_format`).
    *   A função `logger` em `src/common/utils.py` é diferente da `get_logger` importada de `utils.logging` (que se espera que vá para `src/common/logging.py`). Isso pode causar confusão e precisa ser padronizado.

*   **Acoplamento em `core/`**:
    *   Arquivos restantes em `core/` ainda podem ter alto acoplamento entre si. A refatoração precisará continuar para mover mais módulos para `src/modules/` e quebrar essas dependências. Por exemplo, `core/tasks.py` parece ser um forte candidato a ser refatorado ou ter suas responsabilidades distribuídas.

*   **Revisão de `core/dinamic.py` vs `src/modules/dynamic_analysis/dynamic_analyzer.py`**:
    *   O arquivo `core/dinamic.py` (com typo no nome) foi mantido, e seu import para `utils.logging` foi atualizado.
    *   O arquivo `core/dynamic_analyzer.py` (que define a classe `DynamicAnalyzer`) foi movido para `src/modules/dynamic_analysis/dynamic_analyzer.py`.
    *   É preciso clarificar o papel do `core/dinamic.py`. Se for obsoleto, deve ser removido. Se tiver funcionalidade útil e distinta, deve ser apropriadamente nomeado e posicionado na nova estrutura (talvez dentro de `src/modules/dynamic_analysis/` ou como um utilitário específico).

Esta movimentação inicial expôs várias áreas que necessitarão de atenção em tarefas de refatoração subsequentes para alinhar completamente o código com a nova arquitetura e resolver as dependências de importação de forma robusta.
