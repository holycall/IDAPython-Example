import ida_gdl
import ida_kernwin
import ida_funcs

node_cnt = 0
edge_cnt = 0

ea = ida_kernwin.get_screen_ea()
ida_fn = ida_funcs.get_func(ea)
for bl in ida_gdl.FlowChart(ida_fn):    
    node_cnt += 1
    edge_cnt += len(list(bl.succs()))
    
print(f'Number of Nodes = {node_cnt}')
print(f'Number of Edges = {edge_cnt}')
print(f'Cyclomatic Complexity = {edge_cnt - node_cnt + 2}')

