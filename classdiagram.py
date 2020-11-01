from idaapi import GraphViewer, askfile_c

# The  below will only be displayed as bases
ignore_namespaces = ("std", "type_info")

class ClassDiagram(GraphViewer):

    def __init__(self, title, classes):
        self.classes = self.transitive_reduction(classes)
        GraphViewer.__init__(self, title)

    def transitive_reduction(self, graph):
        for u in graph.keys():
            print('u node: ' + u + '(parents: ' + ', '.join([v for v in graph[u]]) + ')')
            for v in graph[u]:
                # Compute the dfs from v
                print('DFS from v node: ' + v)
                dfs = self.dfs_paths(graph, v)
                for node in dfs:
                    print('  - DFS node: ' + str(node))
                    if v != node and node in graph[u]:
                        graph[u].remove(node)
                        print('  # Removed ' + u + ' -> ' + node)
        return graph

    def dfs_paths(self, graph, start, path=None):
        if path is None:
            path = [start]
        # check for leaf
        if start not in graph.keys() or len(graph[start])==0:
            #print('    + ' + str(len(graph[start])))
            #print(start + ': []')
            for p in path:
                yield p
        else:
            #print(start + ': [' + ', '.join([s for s in graph[start]]) + ']')
            print('    + RECUR: ' + ', '.join(set(graph[start]) - set(path)))
            for next in set(graph[start]) - set(path):
                for p in self.dfs_paths(graph, next, path + [next]):
                    print('    + ' + p)
                    yield p

    def add_node(self, class_name):
        if class_name is None:
            return
        if not class_name.startswith(ignore_namespaces):
            print("Adding node: " + class_name)
            new_node = self.AddNode(class_name)
            self.name_to_node[class_name] = new_node

    def OnRefresh(self):
        self.Clear()
        self.name_to_node = {}
        # Create nodes
        for class_name in self.classes.keys():
            # Skipping common namespaces
            self.add_node(class_name)
        # Create edges
        for class_name in self.name_to_node.keys():
            print("Adding edges for: " + class_name)
            node = self.name_to_node[class_name]
            print("bases: " + str(self.classes[class_name]))
            for base_name in self.classes[class_name]:
                if base_name not in self.name_to_node:
                    # Add originally skipped base node
                    self.add_node(base_name)
                base = self.name_to_node.get(base_name)
                if base is not None:
                    self.AddEdge(base, node)
        return True

    def OnGetText(self, node_id):
          return self[node_id]

    # dot file export modified from http://joxeankoret.com
    def OnCommand(self, cmd_id):
        if self.cmd_dot == cmd_id:
            fname = askfile_c(1, "*.dot", "Export DOT file")
            if fname:
                f = open(fname, "wb")
                buf = "digraph G {\n graph [overlap=scale]; node [fontname=Courier]; rankdir=\"LR\";\n\n"
                for c in self.classes.keys():
                    n = self.classes.keys().index(c)
                    buf += ' a%s [shape=box, label = "%s", color="blue"]\n' % (n, c)
                buf += "\n"
                for c in self.classes.keys():
                    class_index = self.classes.keys().index(c)
                    for base in self.classes[c]:
                        if base in self.classes.keys():
                            base_index = self.classes.keys().index(base)
                            buf += ' a%s -> a%s [style = bold]\n' % (class_index, base_index)
                buf += "}"
                f.write(buf)
                f.close()

    def Show(self):
      if not GraphViewer.Show(self):
          return False
      self.cmd_dot = self.AddCommand("Export DOT", "F2")
      return True
