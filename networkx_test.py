__author__ = 'lnn'
import networkx as nx
G=nx.Graph()
H=nx.path_graph(10)
G.add_nodes_from(H)
G.add_edges_from(H.edges())
print(G.nodes())
print(G.edges())
print(G.neighbors(1))
print(nx.shortest_path(G, 2, 7))
print(nx.shortest_path_length(G, 2, 7))