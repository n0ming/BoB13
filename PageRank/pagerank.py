import csv

def load_rank_scores(file_path):
    rank_dict = {}
    with open(file_path, 'r', encoding='utf-8') as j:
        rdr = csv.reader(j)
        next(rdr)  # Skip header
        for line in rdr:
            rank_dict[line[0]] = float(line[1])
    return rank_dict

def load_nodelinks(file_path):
    links_dict = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        rdr = csv.reader(f)
        next(rdr)  # Skip header
        for line in rdr:
            node_page, links = line
            links_dict[node_page] = links.replace('"', '').split()
    return links_dict

def compute_pagerank(links_dict, rank_dict, num_pages, d=0.85, max_iterations=100, tolerance=1.0e-6):
    pageranks = {str(i): 1 / num_pages for i in range(1, num_pages + 1)}
    
    for iteration in range(max_iterations):
        new_pageranks = {}
        for page in pageranks:
            rank_sum = 0
            for node_page, links in links_dict.items():
                if page in links:
                    num_links = len(links)
                    rank_sum += rank_dict[node_page] / num_links
            new_pageranks[page] = (1 - d) / num_pages + d * rank_sum
        
        # Check convergence
        if all(abs(new_pageranks[page] - pageranks[page]) < tolerance for page in pageranks):
            break
        pageranks = new_pageranks
    
    return pageranks

# Load data
pagerank_file = 'D:\\과제\\pagerank.csv'
nodelink_file = 'D:\\과제\\nodelink.csv'

rank_dict = load_rank_scores(pagerank_file)
links_dict = load_nodelinks(nodelink_file)

# Compute PageRank
num_pages = 175
final_pageranks = compute_pagerank(links_dict, rank_dict, num_pages)

# Print final PageRank values
for page, rank in final_pageranks.items():
    print(f"Page {page}: {rank}")
