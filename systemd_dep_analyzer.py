#!/usr/bin/env python3
"""
Systemd Dependency Analyzer
Parses systemd unit files and generates dependency topology graphs.
"""

import argparse
import os
import re
import subprocess
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# Colors for different unit types
UNIT_COLORS = {
    'target': '#FFD700',      # Gold
    'service': '#1E90FF',     # Dodger Blue
    'socket': '#32CD32',      # Lime Green
    'device': '#FF69B4',      # Hot Pink
    'mount': '#9370DB',       # Medium Purple
    'automount': '#8B4513',   # Saddle Brown
    'swap': '#FFA500',        # Orange
    'timer': '#00CED1',       # Dark Turquoise
    'path': '#DC143C',        # Crimson
    'slice': '#2F4F4F',       # Dark Slate Gray
    'scope': '#708090',       # Slate Gray
}

# Colors for different relationship types
RELATION_COLORS = {
    'Requires': '#FF0000',    # Red
    'Wants': '#0000FF',       # Blue
    'After': '#008000',       # Green
    'Before': '#800080',      # Purple
    'Requisite': '#FF4500',   # Orange Red
    'Conflicts': '#8B0000',   # Dark Red
    'PartOf': '#4B0082',      # Indigo
    'BindsTo': '#8B4513',     # Saddle Brown
    'Alias': '#708090',       # Slate Gray
}

class SystemdDependencyAnalyzer:
    def __init__(self, target: str = 'multi-user.target'):
        self.target = target
        self.units: Dict[str, Dict] = {}
        self.relationships: List[Tuple[str, str, str]] = []
        self.unit_paths = [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/run/systemd/system',
            '/usr/local/lib/systemd/system',
            os.path.expanduser('~/.config/systemd/user'),
        ]

    def get_unit_type(self, unit_name: str) -> str:
        """Get the type of a unit from its name."""
        if '.' in unit_name:
            return unit_name.split('.')[-1]
        return 'service'  # Default to service if no extension

    def parse_unit_file(self, unit_path: str) -> Dict:
        """Parse a systemd unit file and extract dependencies."""
        unit_info = {
            'name': os.path.basename(unit_path),
            'path': unit_path,
            'type': self.get_unit_type(os.path.basename(unit_path)),
            'requires': [],
            'wants': [],
            'after': [],
            'before': [],
            'requisite': [],
            'conflicts': [],
            'partof': [],
            'binds_to': [],
            'wanted_by': [],
            'required_by': [],
            'alias': [],
            'description': '',
        }

        try:
            with open(unit_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError):
            return unit_info

        # Extract description
        desc_match = re.search(r'^Description\s*=\s*(.+)$', content, re.MULTILINE)
        if desc_match:
            unit_info['description'] = desc_match.group(1).strip()

        # Extract dependencies
        patterns = {
            'requires': r'^Requires\s*=\s*(.+)$',
            'wants': r'^Wants\s*=\s*(.+)$',
            'after': r'^After\s*=\s*(.+)$',
            'before': r'^Before\s*=\s*(.+)$',
            'requisite': r'^Requisite\s*=\s*(.+)$',
            'conflicts': r'^Conflicts\s*=\s*(.+)$',
            'partof': r'^PartOf\s*=\s*(.+)$',
            'binds_to': r'^BindsTo\s*=\s*(.+)$',
            'wanted_by': r'^WantedBy\s*=\s*(.+)$',
            'required_by': r'^RequiredBy\s*=\s*(.+)$',
            'alias': r'^Alias\s*=\s*(.+)$',
        }

        for key, pattern in patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                deps = match.group(1).strip().split()
                for dep in deps:
                    if dep not in unit_info[key]:
                        unit_info[key].append(dep)

        return unit_info

    def find_unit_file(self, unit_name: str) -> str:
        """Find the path to a unit file by name."""
        # Add .service extension if not present
        if '.' not in unit_name:
            unit_name = f'{unit_name}.service'

        for path in self.unit_paths:
            if not os.path.exists(path):
                continue
            unit_path = os.path.join(path, unit_name)
            if os.path.exists(unit_path):
                return unit_path

            # Check for .wants directories
            wants_dir = os.path.join(path, f'{self.target}.wants')
            if os.path.exists(wants_dir):
                unit_path = os.path.join(wants_dir, unit_name)
                if os.path.exists(unit_path):
                    return os.path.realpath(unit_path)

            # Check for .requires directories
            requires_dir = os.path.join(path, f'{self.target}.requires')
            if os.path.exists(requires_dir):
                unit_path = os.path.join(requires_dir, unit_name)
                if os.path.exists(unit_path):
                    return os.path.realpath(unit_path)

        return None

    def get_all_units_from_systemctl(self) -> Set[str]:
        """Get all units from systemctl list-units command."""
        units = set()
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--all', '--no-pager', '--plain'],
                capture_output=True,
                text=True,
                check=False
            )
            for line in result.stdout.split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    units.add(parts[0])
        except Exception:
            pass
        return units

    def build_dependency_graph(self):
        """Build the dependency graph starting from the target."""
        visited = set()
        queue = [self.target]

        # Get all units from systemctl
        all_systemctl_units = self.get_all_units_from_systemctl()

        while queue:
            unit_name = queue.pop(0)
            if unit_name in visited:
                continue

            visited.add(unit_name)

            # Find unit file
            unit_path = self.find_unit_file(unit_name)

            # If not found in paths, check if it's from systemctl
            if not unit_path and unit_name in all_systemctl_units:
                # Try to get path from systemctl
                try:
                    result = subprocess.run(
                        ['systemctl', 'show', unit_name, '--property=FragmentPath', '--value'],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    path = result.stdout.strip()
                    if path and os.path.exists(path):
                        unit_path = path
                except Exception:
                    pass

            if unit_path:
                unit_info = self.parse_unit_file(unit_path)
                self.units[unit_name] = unit_info

                # Handle aliases - if this unit has aliases, register them
                for alias in unit_info['alias']:
                    # Add the alias as a separate node that points to the actual unit
                    # In systemd, alias is like a symlink, so we treat it similarly
                    if alias not in self.units:
                        self.units[alias] = {
                            'name': alias,
                            'path': unit_path,
                            'type': self.get_unit_type(alias),
                            'requires': [],
                            'wants': [],
                            'after': [],
                            'before': [],
                            'requisite': [],
                            'conflicts': [],
                            'partof': [],
                            'binds_to': [],
                            'wanted_by': [],
                            'required_by': [],
                            'alias': [],
                            'description': f'Alias for {unit_name}',
                        }
                    # Add relationship from alias to actual unit
                    self.relationships.append((alias, unit_name, 'Alias'))
                    if alias not in visited:
                        queue.append(alias)

                # Collect all forward dependencies
                deps = []
                for dep in unit_info['requires']:
                    deps.append((dep, 'Requires'))
                for dep in unit_info['wants']:
                    deps.append((dep, 'Wants'))
                for dep in unit_info['after']:
                    deps.append((dep, 'After'))
                for dep in unit_info['before']:
                    deps.append((dep, 'Before'))
                for dep in unit_info['requisite']:
                    deps.append((dep, 'Requisite'))
                for dep in unit_info['partof']:
                    deps.append((dep, 'PartOf'))
                for dep in unit_info['binds_to']:
                    deps.append((dep, 'BindsTo'))

                # Add forward dependencies to graph
                for dep_name, rel_type in deps:
                    self.relationships.append((unit_name, dep_name, rel_type))
                    if dep_name not in visited:
                        queue.append(dep_name)

                # Handle WantedBy and RequiredBy - these are reverse dependencies
                # If unit A has WantedBy=target B, that means B Wants A
                for wanted_by in unit_info['wanted_by']:
                    self.relationships.append((wanted_by, unit_name, 'Wants'))
                    if wanted_by not in visited:
                        queue.append(wanted_by)

                for required_by in unit_info['required_by']:
                    self.relationships.append((required_by, unit_name, 'Requires'))
                    if required_by not in visited:
                        queue.append(required_by)
            else:
                # Unit not found, add placeholder
                self.units[unit_name] = {
                    'name': unit_name,
                    'path': None,
                    'type': self.get_unit_type(unit_name),
                    'requires': [],
                    'wants': [],
                    'after': [],
                    'before': [],
                    'requisite': [],
                    'conflicts': [],
                    'partof': [],
                    'binds_to': [],
                    'wanted_by': [],
                    'required_by': [],
                    'alias': [],
                    'description': 'Unit file not found',
                }

        # Also scan for units in .wants directories
        self.scan_wants_directories()

    def scan_wants_directories(self):
        """Scan .wants directories for additional dependencies."""
        for path in self.unit_paths:
            if not os.path.exists(path):
                continue

            # Check for target-specific .wants directories
            target_wants = os.path.join(path, f'{self.target}.wants')
            if os.path.exists(target_wants) and os.path.isdir(target_wants):
                for unit_name in os.listdir(target_wants):
                    unit_path = os.path.join(target_wants, unit_name)
                    if os.path.islink(unit_path):
                        real_path = os.path.realpath(unit_path)
                        if unit_name not in self.units:
                            unit_info = self.parse_unit_file(real_path)
                            self.units[unit_name] = unit_info
                        # Add relationship from target to this unit
                        self.relationships.append((self.target, unit_name, 'Wants'))

            # Check for generic .wants directories
            wants_dir = os.path.join(path, 'multi-user.target.wants')
            if os.path.exists(wants_dir) and os.path.isdir(wants_dir) and self.target != 'multi-user.target':
                for unit_name in os.listdir(wants_dir):
                    unit_path = os.path.join(wants_dir, unit_name)
                    if os.path.islink(unit_path):
                        if unit_name not in self.units:
                            real_path = os.path.realpath(unit_path)
                            unit_info = self.parse_unit_file(real_path)
                            self.units[unit_name] = unit_info
                        # Add relationship from multi-user.target to this unit
                        self.relationships.append(('multi-user.target', unit_name, 'Wants'))

    def generate_dot(self) -> str:
        """Generate DOT format graph."""
        dot_lines = [
            'digraph systemd_dependencies {',
            '    rankdir=LR;',
            '    node [fontname="Arial", fontsize=10, style="filled", shape="box"];',
            '    edge [fontname="Arial", fontsize=8];',
        ]

        # Add nodes
        for unit_name, unit_info in self.units.items():
            unit_type = unit_info['type']
            color = UNIT_COLORS.get(unit_type, '#808080')
            
            # Escape special characters in description
            description = unit_info['description'].replace('"', '\\"').replace('\n', ' ')
            
            label = f'{unit_name}\\n{description[:50]}{"..." if len(description) > 50 else ""}'
            dot_lines.append(f'    "{unit_name}" [label="{label}", fillcolor="{color}", color="{color}"];')

        # Add edges
        for source, target, rel_type in self.relationships:
            color = RELATION_COLORS.get(rel_type, '#808080')
            style = 'solid' if rel_type in ['Requires', 'Requisite'] else 'dashed'
            
            dot_lines.append(
                f'    "{source}" -> "{target}" [label="{rel_type}", color="{color}", style="{style}"];'
            )

        # Add legend
        dot_lines.extend([
            '',
            '    subgraph cluster_legend {',
            '        label="Legend";',
            '        style="filled";',
            '        color="#F0F0F0";',
        ])

        # Unit type legend
        for i, (unit_type, color) in enumerate(UNIT_COLORS.items()):
            dot_lines.append(f'        legend_unit_{i} [label="{unit_type}", fillcolor="{color}", style="filled"];')

        # Relationship type legend
        for i, (rel_type, color) in enumerate(RELATION_COLORS.items()):
            dot_lines.append(f'        legend_rel_{i} [label="{rel_type}", style="dotted"];')

        dot_lines.append('    }')
        dot_lines.append('}')

        return '\n'.join(dot_lines)

    def generate_html(self) -> str:
        """Generate interactive HTML graph using D3.js."""
        # Prepare data for D3
        nodes = []
        for unit_name, unit_info in self.units.items():
            nodes.append({
                'id': unit_name,
                'type': unit_info['type'],
                'description': unit_info['description'],
                'color': UNIT_COLORS.get(unit_info['type'], '#808080')
            })

        links = []
        for source, target, rel_type in self.relationships:
            links.append({
                'source': source,
                'target': target,
                'type': rel_type,
                'color': RELATION_COLORS.get(rel_type, '#808080')
            })

        # Generate HTML with embedded D3.js
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Systemd Dependency Graph - {self.target}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }}
        #graph-container {{
            width: 100%;
            height: 800px;
            border: 1px solid #ddd;
            background-color: white;
            position: relative;
        }}
        .node {{
            cursor: pointer;
        }}
        .node text {{
            font-size: 10px;
            pointer-events: none;
        }}
        .link {{
            stroke-width: 1.5px;
        }}
        .link-label {{
            font-size: 8px;
            fill: #666;
        }}
        .tooltip {{
            position: absolute;
            background-color: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
            max-width: 300px;
        }}
        .legend {{
            position: absolute;
            top: 10px;
            right: 10px;
            background-color: rgba(255, 255, 255, 0.9);
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 12px;
        }}
        .legend h3 {{
            margin-top: 0;
            margin-bottom: 10px;
            font-size: 14px;
        }}
        .legend-item {{
            margin-bottom: 5px;
        }}
        .legend-color {{
            display: inline-block;
            width: 12px;
            height: 12px;
            margin-right: 5px;
            vertical-align: middle;
        }}
        #controls {{
            text-align: center;
            margin-bottom: 10px;
        }}
        button {{
            padding: 8px 15px;
            margin: 0 5px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }}
        button:hover {{
            background-color: #45a049;
        }}
    </style>
</head>
<body>
    <h1>Systemd Dependency Graph - {self.target}</h1>
    <div id="controls">
        <button id="zoom-in">Zoom In</button>
        <button id="zoom-out">Zoom Out</button>
        <button id="reset-zoom">Reset</button>
    </div>
    <div id="graph-container">
        <div class="legend">
            <h3>Unit Types</h3>
'''

        # Add unit type legend
        for unit_type, color in UNIT_COLORS.items():
            html += f'            <div class="legend-item"><span class="legend-color" style="background-color: {color};"></span>{unit_type}</div>\n'

        html += '''            <h3>Relationships</h3>
'''

        # Add relationship legend
        for rel_type, color in RELATION_COLORS.items():
            html += f'            <div class="legend-item"><span class="legend-color" style="background-color: {color};"></span>{rel_type}</div>\n'

        html += '''        </div>
        <div class="tooltip" id="tooltip"></div>
    </div>

    <script>
        // Data
        const nodes = ''' + str(nodes).replace("'", '"') + ''';
        const links = ''' + str(links).replace("'", '"') + ''';

        // Setup
        const container = document.getElementById('graph-container');
        const width = container.clientWidth;
        const height = container.clientHeight;

        const svg = d3.select('#graph-container')
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        const g = svg.append('g');

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);

        // Zoom controls
        document.getElementById('zoom-in').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.scaleBy, 1.3);
        });

        document.getElementById('zoom-out').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.scaleBy, 0.7);
        });

        document.getElementById('reset-zoom').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);
        });

        // Tooltip
        const tooltip = d3.select('#tooltip');

        // Simulation
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(30));

        // Links
        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .join('line')
            .attr('class', 'link')
            .attr('stroke', d => d.color)
            .attr('stroke-dasharray', d => d.type === 'Wants' ? '5,5' : null);

        // Link labels
        const linkLabel = g.append('g')
            .selectAll('text')
            .data(links)
            .join('text')
            .attr('class', 'link-label')
            .text(d => d.type);

        // Nodes
        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .join('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        // Node rectangles
        node.append('rect')
            .attr('width', d => Math.max(d.id.length * 8 + 10, 60))
            .attr('height', 30)
            .attr('fill', d => d.color)
            .attr('rx', 5)
            .attr('ry', 5);

        // Node text
        node.append('text')
            .attr('x', d => (Math.max(d.id.length * 8 + 10, 60)) / 2)
            .attr('y', 18)
            .attr('text-anchor', 'middle')
            .attr('fill', 'white')
            .text(d => d.id.length > 20 ? d.id.substring(0, 18) + '...' : d.id);

        // Tooltip events
        node.on('mouseover', (event, d) => {
            tooltip
                .style('display', 'block')
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px')
                .html(`<strong>${d.id}</strong><br>Type: ${d.type}<br>${d.description || 'No description'}`);
        })
        .on('mousemove', (event) => {
            tooltip
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px');
        })
        .on('mouseout', () => {
            tooltip.style('display', 'none');
        });

        // Tick function
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            linkLabel
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2);

            node.attr('transform', d => `translate(${d.x - Math.max(d.id.length * 8 + 10, 60) / 2}, ${d.y - 15})`);
        });

        // Drag functions
        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }

        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }
    </script>
</body>
</html>
'''
        return html

    def save_output(self, output_format: str, output_path: str):
        """Save the graph to a file."""
        if output_format == 'dot':
            content = self.generate_dot()
        elif output_format == 'html':
            content = self.generate_html()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"Graph saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Systemd Dependency Analyzer - Generate dependency topology graphs from systemd unit files'
    )
    parser.add_argument(
        '-t', '--target',
        default='multi-user.target',
        help='Target unit to analyze (default: multi-user.target)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['dot', 'html'],
        default='dot',
        help='Output format (default: dot)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: systemd_deps.{format})'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output'
    )

    args = parser.parse_args()

    # Set default output path
    if not args.output:
        args.output = f'systemd_deps.{args.format}'

    # Create analyzer and build graph
    analyzer = SystemdDependencyAnalyzer(target=args.target)
    
    if args.verbose:
        print(f"Analyzing dependencies for target: {args.target}")
        print("Building dependency graph...")
    
    analyzer.build_dependency_graph()
    
    if args.verbose:
        print(f"Found {len(analyzer.units)} units")
        print(f"Found {len(analyzer.relationships)} relationships")
        
        # Print sample units for verification
        if 'sshd.service' in analyzer.units:
            print(f"\nsshd.service found!")
            sshd_info = analyzer.units['sshd.service']
            print(f"  Type: {sshd_info['type']}")
            print(f"  Description: {sshd_info['description']}")
        
        # Check network.target relationship to sshd
        for source, target, rel_type in analyzer.relationships:
            if source == 'network.target' and target == 'sshd.service':
                print(f"\nFound relationship: network.target -> sshd.service ({rel_type})")
            if source == 'sshd.service' and target == 'network.target':
                print(f"\nFound relationship: sshd.service -> network.target ({rel_type})")

    # Save output
    analyzer.save_output(args.format, args.output)

    print("\nAnalysis complete!")
    if args.format == 'html':
        print("You can open the HTML file in a browser to view the interactive graph.")
    elif args.format == 'dot':
        print("You can use Graphviz to convert the DOT file to an image:")
        print(f"  dot -Tpng {args.output} -o systemd_deps.png")


if __name__ == '__main__':
    main()
