import r2pipe
import json
import os
import subprocess
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import openai
from src.common.utils import logger, get_file_format
from .output import generate_markdown, generate_pdf, generate_learning_doc

# BinaryAnalyzer class has been moved to src.modules.static_analysis.static_analyzer
# Any other task-related functions/classes for the core module would go here.
# If this file becomes empty aside from imports, it might be a candidate for removal in future refactoring.

# Example: If there were other task functions, they would remain.
# def another_core_task():
#     pass
#
# As there are no other functions or classes, this file is now mostly imports
# and the .output functions that were used by the removed BinaryAnalyzer's run_full_analysis method.
# These .output imports might be removed if no other part of 'core' module uses them directly.
# For now, they are kept as other parts of 'core' might still be refactored to use them.

# Final check: ensure `logger` and `get_file_format` from `src.common.utils`
# and the .output imports are actually used by other parts of `core` if this file
# is to be kept. If not, these imports are also unused in this file's new context.
