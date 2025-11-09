"""
Super Pseudo - IDA Pro Plugin
Recursively inlines function calls in decompiled pseudocode
"""

import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_lines
import idc
from ida_hexrays import *

# Import configuration
try:
    from . import config
except ImportError:
    # If config doesn't exist, use defaults
    class config:
        DEFAULT_DEPTH = 3
        MAX_DEPTH = 10
        ASK_DEPTH_EVERY_TIME = True
        PRESERVE_SYNTAX_HIGHLIGHTING = True


class FunctionInliner(ctree_visitor_t):
    """
    Visitor that collects function calls from the ctree
    """
    def __init__(self, visited_funcs, depth, max_depth):
        ctree_visitor_t.__init__(self, CV_FAST)
        self.calls = []  # List of (ea, cexpr_t) tuples
        self.visited_funcs = visited_funcs
        self.depth = depth
        self.max_depth = max_depth

    def visit_expr(self, expr):
        """Visit each expression node"""
        if expr.op == cot_call:
            # Check if this is a direct function call
            if expr.x.op == cot_obj:
                func_ea = expr.x.obj_ea
                # Only inline if we haven't visited this function and haven't exceeded max depth
                if func_ea not in self.visited_funcs and self.depth < self.max_depth:
                    self.calls.append((func_ea, expr))
        return 0


class InlineInfo:
    """Information about a function to be inlined"""
    def __init__(self, ea, name, cfunc):
        self.ea = ea
        self.name = name
        self.cfunc = cfunc
        self.args = []  # List of argument expressions
        self.params = []  # List of parameter names


class PseudocodeBuilder:
    """Builds pseudocode string from ctree with proper indentation"""
    def __init__(self):
        self.lines = []
        self.indent = 0

    def add_line(self, text):
        """Add a line with current indentation"""
        self.lines.append("  " * self.indent + text)

    def increase_indent(self):
        self.indent += 1

    def decrease_indent(self):
        if self.indent > 0:
            self.indent -= 1

    def get_result(self):
        return '\n'.join(self.lines)


class SuperPseudoGenerator:
    """
    Main class for generating super pseudocode with recursive inlining
    """
    def __init__(self, max_depth=3):
        self.max_depth = max_depth
        self.inline_count = 0

    def get_func_name(self, ea):
        """Get function name from address"""
        name = idc.get_func_name(ea)
        if not name:
            name = f"sub_{ea:X}"
        return name

    def decompile_function(self, ea):
        """Decompile a function at the given address"""
        try:
            cfunc = ida_hexrays.decompile(ea)
            return cfunc
        except ida_hexrays.DecompilationFailure:
            return None

    def get_expr_string(self, expr):
        """Convert an expression to string"""
        # This is a simplified version - in reality you'd want to handle all expression types
        printer = qstring()
        expr.print1(printer, None)
        return str(printer)

    def extract_function_body(self, cfunc):
        """
        Extract the function body statements, excluding the function signature and closing brace

        Args:
            cfunc: The decompiled function

        Returns:
            List of strings representing the body lines
        """
        sv = cfunc.get_pseudocode()
        lines = []

        for i in range(len(sv)):
            line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        # Remove function signature (first line) and closing brace (last line)
        if len(lines) > 2:
            # Skip the function declaration line and the final closing brace
            body_lines = []
            for i in range(1, len(lines) - 1):
                line = lines[i].rstrip()
                # Remove one level of indentation
                if line.startswith('  '):
                    line = line[2:]
                body_lines.append(line)
            return body_lines
        return []

    def get_function_params(self, cfunc):
        """Extract parameter names from a function"""
        params = []
        # Get function type
        func_type = cfunc.type
        if func_type:
            # Iterate through function arguments
            for i in range(func_type.get_nargs()):
                arg_name = cfunc.lvars[i].name if i < len(cfunc.lvars) else f"arg{i}"
                params.append(arg_name)
        return params

    def get_function_pseudocode(self, ea, visited_funcs=None, depth=0, inline_simple=True, preserve_tags=True):
        """
        Recursively generate pseudocode with inlined function calls

        Args:
            ea: Address of the function to decompile
            visited_funcs: Set of already visited function addresses (for cycle detection)
            depth: Current recursion depth
            inline_simple: Whether to inline simple functions directly or show as blocks
            preserve_tags: Whether to preserve IDA color tags for syntax highlighting

        Returns:
            List of lines (with or without tags) containing the pseudocode with inlined calls
        """
        if visited_funcs is None:
            visited_funcs = set()

        # Prevent infinite recursion
        if ea in visited_funcs or depth >= self.max_depth:
            return None

        visited_funcs.add(ea)

        # Decompile the function
        cfunc = self.decompile_function(ea)
        if not cfunc:
            visited_funcs.remove(ea)
            return None

        # Get the pseudocode as lines
        sv = cfunc.get_pseudocode()
        lines = []
        for i in range(len(sv)):
            # Preserve tags if requested, otherwise remove them
            if preserve_tags:
                line = sv[i].line
            else:
                line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        # Find all function calls in this function
        visitor = FunctionInliner(visited_funcs, depth, self.max_depth)
        visitor.apply_to(cfunc.body, None)

        # Build a mapping of function calls to their inlined code
        inlined_functions = {}
        for func_ea, call_expr in visitor.calls:
            func_name = self.get_func_name(func_ea)

            # Debug output
            if depth == 0:
                print(f"[Super Pseudo] Found call to {func_name} at 0x{func_ea:X}")

            inlined_code = self.get_function_pseudocode(func_ea, visited_funcs.copy(), depth + 1, inline_simple, preserve_tags)
            if inlined_code:
                # Store both full name and address for matching
                inlined_functions[func_ea] = {
                    'name': func_name,
                    'code': inlined_code,
                    'ea': func_ea,
                    'expr': call_expr
                }
                if depth == 0:
                    print(f"[Super Pseudo] Successfully inlined {func_name} ({len(inlined_code)} lines)")
            else:
                if depth == 0:
                    print(f"[Super Pseudo] Could not inline {func_name} (decompilation failed or max depth)")

        visited_funcs.remove(ea)

        # Build the result with inlined functions
        if inlined_functions:
            result = []
            if depth == 0:
                # Add header (plain text, no tags)
                result.append(f"// ========== SUPER PSEUDO ==========")
                result.append(f"// Inlining depth: {self.max_depth}")
                result.append(f"// Functions inlined: {len(inlined_functions)}")
                result.append("")

            # Track which functions we've already inlined on each line
            inlined_on_line = set()

            for line in lines:
                result.append(line)

                # Check if this line contains any of the inlined function calls
                # Remove tags temporarily for string matching
                line_plain = ida_lines.tag_remove(line) if preserve_tags else line

                # Try to match function calls by name
                for func_ea, inline_info in inlined_functions.items():
                    func_name = inline_info['name']

                    should_inline = False

                    # Strategy 1: func_name(
                    if func_name + "(" in line_plain:
                        should_inline = True
                    # Strategy 2: Just the name appearing (for assignments)
                    elif func_name in line_plain and '=' in line_plain:
                        should_inline = True
                    # Strategy 3: Check base name for complex mangled names
                    else:
                        # Extract last component after common separators
                        base_name = func_name.split('.')[-1].split('_')[-1]
                        if len(base_name) > 3 and base_name in line_plain:
                            should_inline = True

                    # Only inline each function once per line
                    if should_inline and func_ea not in inlined_on_line:
                        inlined_on_line.add(func_ea)
                        self.inline_count += 1

                        # Add the inlined function code
                        result.append("")
                        result.append(f"  // ========== BEGIN INLINED: {func_name} (depth {depth + 1}) ==========")

                        # Add the inlined code with proper indentation
                        if isinstance(inline_info['code'], list):
                            for inline_line in inline_info['code']:
                                stripped = ida_lines.tag_remove(inline_line).strip() if preserve_tags else inline_line.strip()
                                if stripped:
                                    result.append("  " + inline_line)
                        else:
                            for inline_line in inline_info['code'].split('\n'):
                                if inline_line.strip():
                                    result.append("  " + inline_line)

                        result.append(f"  // ========== END INLINED: {func_name} ==========")
                        result.append("")

                # Clear per-line tracking
                inlined_on_line.clear()

            if depth == 0:
                result.append("")
                result.append(f"// Total inline operations: {self.inline_count}")
                result.append(f"// ========== END SUPER PSEUDO ==========")

            return result
        else:
            return lines


class SuperPseudoActionHandler(ida_kernwin.action_handler_t):
    """
    Action handler for the Super Pseudo plugin
    """
    # Class variable to remember the last depth setting
    last_depth = config.DEFAULT_DEPTH

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """Called when the action is triggered"""
        # Get current function
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)

        if not func:
            ida_kernwin.warning("Please position the cursor in a function")
            return 0

        # Check if decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.warning("Hex-Rays decompiler is not available")
            return 0

        # Determine depth
        if config.ASK_DEPTH_EVERY_TIME:
            # Ask user for inlining depth
            depth = ida_kernwin.ask_long(
                SuperPseudoActionHandler.last_depth,
                f"Enter maximum inlining depth (1-{config.MAX_DEPTH}):"
            )

            # Validate depth
            if depth is None:
                # User cancelled
                return 0

            if depth < 1:
                depth = 1
            elif depth > config.MAX_DEPTH:
                ida_kernwin.warning(f"Maximum depth is {config.MAX_DEPTH}. Using {config.MAX_DEPTH}.")
                depth = config.MAX_DEPTH

            # Remember this depth for next time
            SuperPseudoActionHandler.last_depth = depth
        else:
            # Use configured default depth
            depth = config.DEFAULT_DEPTH

        # Generate super pseudocode
        func_name = idc.get_func_name(func.start_ea)
        print(f"[Super Pseudo] Generating super pseudocode for {func_name} (depth: {depth})...")
        generator = SuperPseudoGenerator(max_depth=depth)
        pseudocode_lines = generator.get_function_pseudocode(func.start_ea, preserve_tags=config.PRESERVE_SYNTAX_HIGHLIGHTING)

        if not pseudocode_lines:
            ida_kernwin.warning("Failed to generate super pseudocode")
            return 0

        # Display the result
        self.show_pseudocode(func_name, pseudocode_lines, depth)
        print(f"[Super Pseudo] Done! {generator.inline_count} function(s) inlined.")

        return 1

    def update(self, ctx):
        """Check if the action should be enabled"""
        # Enable in pseudocode view
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def show_pseudocode(self, func_name, pseudocode_lines, depth):
        """Display the pseudocode in a custom viewer with syntax highlighting"""
        title = f"Super Pseudo: {func_name} [depth={depth}]"

        # Close existing viewer if it exists
        widget = ida_kernwin.find_widget(title)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        # Create new viewer with syntax highlighting support
        viewer = ida_kernwin.simplecustviewer_t()
        if viewer.Create(title):
            # Add each line (with color tags preserved)
            for line in pseudocode_lines:
                viewer.AddLine(line)
            viewer.Show()
