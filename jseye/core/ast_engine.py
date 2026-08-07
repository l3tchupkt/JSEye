"""Advanced AST analysis engine for JavaScript intelligence v2."""

import re
import ast
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from .logging import get_logger
from .exceptions import JSEyeParsingError

logger = get_logger(__name__)


@dataclass
class Variable:
    """Represents a JavaScript variable with its lineage."""
    name: str
    value: Optional[str]
    type: str
    line: int
    scope: str
    assignments: List[Tuple[int, str]]  # (line, value) pairs


@dataclass
class FunctionCall:
    """Represents a function call with context."""
    function_name: str
    arguments: List[str]
    line: int
    context: str
    is_async: bool = False


@dataclass
class EndpointPattern:
    """Represents a normalized endpoint pattern."""
    original: str
    normalized: str
    parameters: List[str]
    pattern_type: str  # 'id', 'uuid', 'hash', 'timestamp', 'static'


class JSASTAnalyzer:
    """Advanced JavaScript AST analyzer with constant propagation and flow tracking."""
    
    def __init__(self):
        self.variables: Dict[str, Variable] = {}
        self.function_calls: List[FunctionCall] = []
        self.string_builders: Dict[str, List[str]] = {}
        self.template_literals: List[str] = []
        self.dynamic_imports: List[str] = []
        
        # Patterns for endpoint normalization
        self.id_patterns = [
            (r'/\d+(?=/|$)', '/{id}'),  # Numeric IDs
            (r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)', '/{uuid}'),  # UUIDs
            (r'/[0-9a-f]{32,64}(?=/|$)', '/{hash}'),  # Hash patterns
            (r'/\d{10,13}(?=/|$)', '/{timestamp}'),  # Timestamps
            (r'/[A-Za-z0-9_-]{20,}(?=/|$)', '/{token}'),  # Long tokens
        ]
    
    def analyze(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Perform comprehensive AST analysis of JavaScript content."""
        try:
            # Clean and prepare content
            cleaned_content = self._clean_js_content(content)
            
            # Extract variables and their assignments
            self._extract_variables(cleaned_content)
            
            # Perform constant propagation
            self._propagate_constants()
            
            # Extract function calls
            self._extract_function_calls(cleaned_content)
            
            # Reconstruct template literals
            self._reconstruct_template_literals(cleaned_content)
            
            # Extract dynamic imports
            self._extract_dynamic_imports(cleaned_content)
            
            # Extract and normalize endpoints
            endpoints = self._extract_and_normalize_endpoints(cleaned_content)
            
            # Detect string concatenation chains
            concatenated_strings = self._detect_string_concatenation(cleaned_content)
            
            # Extract decoded strings
            decoded_strings = self._extract_decoded_strings(cleaned_content)
            
            return {
                'source_url': source_url,
                'variables': [vars(v) for v in self.variables.values()],
                'function_calls': [vars(fc) for fc in self.function_calls],
                'template_literals': self.template_literals,
                'dynamic_imports': self.dynamic_imports,
                'endpoints': endpoints,
                'concatenated_strings': concatenated_strings,
                'decoded_strings': decoded_strings,
                'string_builders': self.string_builders
            }
            
        except Exception as e:
            logger.error(f"AST analysis failed for {source_url}", error=str(e))
            raise JSEyeParsingError(f"AST analysis failed: {str(e)}", source=source_url)
    
    def _clean_js_content(self, content: str) -> str:
        """Clean JavaScript content for analysis."""
        # Remove single-line comments but avoid URLs in strings/templates
        # First, protect template literals and strings
        protected_content = content
        
        # Remove single-line comments (but not // in strings or template literals)
        lines = protected_content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Simple approach: only remove // comments that are not inside quotes or backticks
            in_string = False
            in_template = False
            quote_char = None
            i = 0
            cleaned_line = ""
            
            while i < len(line):
                char = line[i]
                
                if not in_string and not in_template:
                    if char == '`':
                        in_template = True
                        cleaned_line += char
                    elif char in ['"', "'"]:
                        in_string = True
                        quote_char = char
                        cleaned_line += char
                    elif char == '/' and i + 1 < len(line) and line[i + 1] == '/':
                        # Found comment outside of strings/templates, stop processing this line
                        break
                    else:
                        cleaned_line += char
                elif in_string:
                    cleaned_line += char
                    if char == quote_char and (i == 0 or line[i-1] != '\\'):
                        in_string = False
                        quote_char = None
                elif in_template:
                    cleaned_line += char
                    if char == '`' and (i == 0 or line[i-1] != '\\'):
                        in_template = False
                
                i += 1
            
            cleaned_lines.append(cleaned_line)
        
        content = '\n'.join(cleaned_lines)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Normalize whitespace but preserve structure
        content = re.sub(r'[ \t]+', ' ', content)
        
        return content
    
    def _extract_variables(self, content: str) -> None:
        """Extract variable declarations and assignments with lineage tracking."""
        lines = content.split('\n')
        
        # Patterns for variable declarations
        var_patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=\s*([^;]+);?',
            r'(\w+)\s*=\s*([^;]+);?',
            r'(\w+)\s*:\s*([^,}]+)',  # Object properties
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in var_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name = match.group(1)
                    var_value = match.group(2).strip()
                    
                    # Skip very common loop variables
                    if var_name in ['i', 'j', 'k', 'x', 'y', 'z', 'e']:
                        continue
                    
                    # Determine variable type
                    var_type = self._determine_variable_type(var_value)
                    
                    if var_name in self.variables:
                        # Update existing variable
                        self.variables[var_name].assignments.append((line_num, var_value))
                    else:
                        # Create new variable
                        self.variables[var_name] = Variable(
                            name=var_name,
                            value=var_value,
                            type=var_type,
                            line=line_num,
                            scope='global',  # Simplified scope detection
                            assignments=[(line_num, var_value)]
                        )
    
    def _determine_variable_type(self, value: str) -> str:
        """Determine the type of a variable based on its value."""
        value = value.strip()
        
        if value.startswith('"') or value.startswith("'") or value.startswith('`'):
            return 'string'
        elif value.isdigit() or re.match(r'^\d+\.\d+$', value):
            return 'number'
        elif value in ['true', 'false']:
            return 'boolean'
        elif value.startswith('['):
            return 'array'
        elif value.startswith('{'):
            return 'object'
        elif value.startswith('function') or '=>' in value:
            return 'function'
        else:
            return 'unknown'
    
    def _propagate_constants(self) -> None:
        """Perform constant propagation to resolve variable values."""
        max_iterations = 5  # Prevent infinite loops
        
        for _ in range(max_iterations):
            changed = False
            
            for var in self.variables.values():
                if var.type == 'string' and var.value:
                    # Try to resolve variable references in string values
                    original_value = var.value
                    resolved_value = self._resolve_variable_references(var.value)
                    
                    if resolved_value != original_value:
                        var.value = resolved_value
                        changed = True
            
            if not changed:
                break
    
    def _resolve_variable_references(self, value: str) -> str:
        """Resolve variable references in a string value."""
        # Simple variable reference resolution
        for var_name, var_obj in self.variables.items():
            if var_obj.type == 'string' and var_obj.value:
                # Replace variable references
                pattern = rf'\b{re.escape(var_name)}\b'
                if re.search(pattern, value):
                    clean_value = var_obj.value.strip('"\'`')
                    value = re.sub(pattern, clean_value, value)
        
        return value
    
    def _extract_function_calls(self, content: str) -> None:
        """Extract function calls with context analysis."""
        lines = content.split('\n')
        
        # Patterns for function calls
        call_patterns = [
            r'(\w+)\s*\(\s*([^)]*)\s*\)',  # Simple function calls
            r'(\w+)\.(\w+)\s*\(\s*([^)]*)\s*\)',  # Method calls
            r'await\s+(\w+)\s*\(\s*([^)]*)\s*\)',  # Async calls
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in call_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    if len(match.groups()) == 2:
                        func_name = match.group(1)
                        args = match.group(2)
                    else:
                        func_name = f"{match.group(1)}.{match.group(2)}"
                        args = match.group(3)
                    
                    # Parse arguments
                    arg_list = self._parse_function_arguments(args)
                    
                    # Check if it's an async call
                    is_async = 'await' in line or 'async' in line
                    
                    self.function_calls.append(FunctionCall(
                        function_name=func_name,
                        arguments=arg_list,
                        line=line_num,
                        context=line.strip(),
                        is_async=is_async
                    ))
    
    def _parse_function_arguments(self, args_str: str) -> List[str]:
        """Parse function arguments from string."""
        if not args_str.strip():
            return []
        
        # Simple argument parsing (doesn't handle nested objects/arrays perfectly)
        args = []
        current_arg = ""
        paren_depth = 0
        bracket_depth = 0
        in_string = False
        string_char = None
        
        for char in args_str:
            if char in ['"', "'", '`'] and not in_string:
                in_string = True
                string_char = char
            elif char == string_char and in_string:
                in_string = False
                string_char = None
            elif not in_string:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth -= 1
                elif char == '[':
                    bracket_depth += 1
                elif char == ']':
                    bracket_depth -= 1
                elif char == ',' and paren_depth == 0 and bracket_depth == 0:
                    args.append(current_arg.strip())
                    current_arg = ""
                    continue
            
            current_arg += char
        
        if current_arg.strip():
            args.append(current_arg.strip())
        
        return args
    
    def _reconstruct_template_literals(self, content: str) -> None:
        """Reconstruct template literals with variable substitution."""
        # Find template literals - improved pattern to handle multiline
        template_pattern = r'`([^`]*?)`'
        matches = re.finditer(template_pattern, content, re.DOTALL)
        
        for match in matches:
            template = match.group(1)
            
            # Resolve variables in template
            resolved_template = self._resolve_template_variables(template)
            self.template_literals.append(resolved_template)
    
    def _resolve_template_variables(self, template: str) -> str:
        """Resolve variables in template literals."""
        # Find ${variable} patterns
        var_pattern = r'\$\{([^}]+)\}'
        
        def replace_var(match):
            var_expr = match.group(1)
            # Try to resolve the variable
            if var_expr in self.variables:
                var_value = self.variables[var_expr].value
                if var_value:
                    return var_value.strip('"\'`')
            return f"${{{var_expr}}}"  # Keep original if can't resolve
        
        return re.sub(var_pattern, replace_var, template)
    
    def _extract_dynamic_imports(self, content: str) -> None:
        """Extract dynamic import() calls."""
        import_patterns = [
            r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'import\s*\(\s*([^)]+)\s*\)',  # Variable imports
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Resolve variable if it's not a direct string
                if match in self.variables:
                    resolved = self.variables[match].value
                    if resolved:
                        self.dynamic_imports.append(resolved.strip('"\'`'))
                else:
                    self.dynamic_imports.append(match)
    
    def _extract_and_normalize_endpoints(self, content: str) -> List[EndpointPattern]:
        """Extract and normalize API endpoints."""
        endpoints = []
        
        # Extract potential endpoints
        endpoint_patterns = [
            r'["\']([/][a-zA-Z0-9/_.-]+)["\']',  # Quoted paths
            r'`([/][^`]*)`',  # Template literal paths
        ]
        
        found_endpoints = set()
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            found_endpoints.update(matches)
        
        # Normalize endpoints
        for endpoint in found_endpoints:
            normalized = self._normalize_endpoint(endpoint)
            if normalized:
                endpoints.append(normalized)
        
        return [vars(ep) for ep in endpoints]
    
    def _normalize_endpoint(self, endpoint: str) -> Optional[EndpointPattern]:
        """Normalize an endpoint by replacing dynamic parts with patterns."""
        if len(endpoint) < 2 or not endpoint.startswith('/'):
            return None
        
        original = endpoint
        normalized = endpoint
        parameters = []
        pattern_types = []
        
        # Apply normalization patterns
        for pattern, replacement in self.id_patterns:
            if re.search(pattern, normalized):
                normalized = re.sub(pattern, replacement, normalized)
                param_name = replacement.strip('{}/')
                parameters.append(param_name)
                pattern_types.append(param_name)
        
        # Determine overall pattern type
        if not pattern_types:
            pattern_type = 'static'
        elif len(set(pattern_types)) == 1:
            pattern_type = pattern_types[0]
        else:
            pattern_type = 'mixed'
        
        return EndpointPattern(
            original=original,
            normalized=normalized,
            parameters=parameters,
            pattern_type=pattern_type
        )
    
    def _detect_string_concatenation(self, content: str) -> List[str]:
        """Detect string concatenation chains."""
        concatenated = []
        
        # Pattern for string concatenation
        concat_pattern = r'["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']'
        matches = re.findall(concat_pattern, content)
        
        for match in matches:
            concatenated.append(''.join(match))
        
        # Multi-part concatenation
        multi_concat_pattern = r'(["\'][^"\']*["\'](?:\s*\+\s*["\'][^"\']*["\'])+)'
        multi_matches = re.findall(multi_concat_pattern, content)
        
        for match in multi_matches:
            # Extract individual strings and concatenate
            string_parts = re.findall(r'["\']([^"\']*)["\']', match)
            if len(string_parts) > 1:
                concatenated.append(''.join(string_parts))
        
        return concatenated
    
    def _extract_decoded_strings(self, content: str) -> List[Dict[str, str]]:
        """Extract and decode encoded strings."""
        decoded = []
        
        # Base64 decoding patterns
        b64_patterns = [
            r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)',
            r'Buffer\.from\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*,\s*["\']base64["\']\s*\)',
        ]
        
        for pattern in b64_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    import base64
                    decoded_bytes = base64.b64decode(match)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if decoded_str and len(decoded_str) > 3:
                        decoded.append({
                            'type': 'base64',
                            'encoded': match[:50] + '...' if len(match) > 50 else match,
                            'decoded': decoded_str
                        })
                except Exception:
                    continue
        
        # Hex decoding patterns
        hex_patterns = [
            r'parseInt\s*\(\s*["\']([0-9a-fA-F]+)["\']\s*,\s*16\s*\)',
            r'0x([0-9a-fA-F]+)',
        ]
        
        for pattern in hex_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    if len(match) % 2 == 0 and len(match) >= 4:
                        decoded_bytes = bytes.fromhex(match)
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        if decoded_str and len(decoded_str) > 2:
                            decoded.append({
                                'type': 'hex',
                                'encoded': match,
                                'decoded': decoded_str
                            })
                except Exception:
                    continue
        
        return decoded