import networkx as nx
import plotly.graph_objects as go
import pandas as pd
import streamlit as st

def build_network_graph(df_cves, df_products, vendor_name):
    """
    Builds a force-directed network graph of Vendor -> Products -> CVEs.
    """
    G = nx.Graph()
    
    # 1. Add Vendor Node (Center)
    G.add_node(vendor_name, type='vendor', size=40, color='#FFFFFF', title=vendor_name)
    
    # 2. Process Products (Top 15 by *Filtered* CVE count)
    # Filter products to those associated with the CVEs in df_cves (which is filtered)
    relevant_products_df = df_products[df_products['cve_id'].isin(df_cves['cve_id'])]
    
    if relevant_products_df.empty:
        # Fallback to avoid error if no data
        return go.Figure()

    prod_counts = relevant_products_df['product'].value_counts().head(15)
    
    # Add Product Nodes
    for prod, count in prod_counts.items():
        # Scale size by log or sqrt of count
        size = 15 + (count ** 0.5) * 2
        G.add_node(prod, type='product', size=size, color='#8B5CF6', title=f"{prod} ({count} CVEs)")
        G.add_edge(vendor_name, prod, weight=2)
        
    # 3. Add CVE Nodes (Leaves) associated with these products
    # Filter products to top 15
    top_products = prod_counts.index.tolist()
    relevant_prods = df_products[df_products['product'].isin(top_products)]
    
    # We only want to show CVEs that are in our filtered df_cves (context aware)
    # Join relevant_prods with df_cves to get severity
    cve_nodes = relevant_prods.merge(df_cves[['cve_id', 'cvss_v31_severity', 'cvss_v31_base_score']], on='cve_id', how='inner')
    
    # Limit CVEs? If 1000s, graph explodes. 
    # Let's show only Critical and High to keep it readable, or limit total?
    # Or just show Top 50 by severity?
    
    # Let's verify count.
    if len(cve_nodes) > 150:
        cve_nodes = cve_nodes.sort_values('cvss_v31_base_score', ascending=False).head(150)
    
    sev_colors = {
        'CRITICAL': '#DC2626', 
        'HIGH': '#EA580C', 
        'MEDIUM': '#D97706', 
        'LOW': '#059669', 
        'UNKNOWN': '#9CA3AF'
    }
    
    for _, row in cve_nodes.iterrows():
        cve = row['cve_id']
        prod = row['product']
        sev = row.get('cvss_v31_severity', 'UNKNOWN')
        score = row.get('cvss_v31_base_score', 0)
        
        col = sev_colors.get(sev, '#9CA3AF')
        
        if not G.has_node(cve):
            G.add_node(cve, type='cve', size=8, color=col, title=f"{cve} ({sev} {score})")
        
        G.add_edge(prod, cve, weight=1)

    # 4. Compute Layout
    # k parameter controls node spacing.
    pos = nx.spring_layout(G, k=0.5, iterations=50, seed=42)
    
    # 5. Build Plotly Traces
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#404040'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(G.nodes[node]['title'])
        node_color.append(G.nodes[node]['color'])
        node_size.append(G.nodes[node]['size'])

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hovertext=node_text,
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color=node_color,
            size=node_size,
            line_width=1,
            line_color='#1A1A1A'
        )
    )

    # 6. Create Figure
    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                showlegend=False,
                hovermode='closest',
                margin=dict(b=0,l=0,r=0,t=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
             )
             
    return fig
