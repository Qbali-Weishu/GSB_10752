#!/usr/bin/env python3
"""
Systemd Dependency Analyzer - Enhanced Version
Parses systemd unit files and generates dependency topology graphs.

Enhancements:
- Default dependencies (DefaultDependencies)
- Wildcard dependency expansion
- Enhanced .wants/.requires directory scanning
- Duplicate edge removal
- Placeholder unit removal
- Conditional dependency detection
- Hierarchical layout for HTML
- Search and highlight functionality
"""

import argparse
import os
import re
import subprocess
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

UNIT_COLORS = {
    'target': '#FFD700',
    'service': '#1E90FF',
    'socket': '#32CD32',
    'device': '#FF69B4',
    'mount': '#9370DB',
    'automount': '#8B4513',
    'swap': '#FFA500',
    'timer': '#00CED1',
    'path': '#DC143C',
    'slice': '#2F4F4F',
    'scope': '#708090',
}

RELATION_COLORS = {
    'Requires': '#FF0000',
    'Wants': '#0000FF',
    'After': '#008000',
    'Before': '#800080',
    'Requisite': '#FF4500',
    'Conflicts': '#8B0000',
    'PartOf': '#4B0082',
    'BindsTo': '#8B4513',
    'Alias': '#708090',
    'Default': '#A0522D',
    'UpheldBy': '#20B2AA',
}

DEFAULT_DEPENDENCIES = {
    'service': {
        'DefaultDependencies': {
            'Requires': ['sysinit.target'],
            'After': ['sysinit.target', 'basic.target'],
            'Before': ['shutdown.target'],
            'Conflicts': ['shutdown.target'],
        }
    },
    'socket': {
        'DefaultDependencies': {
            'Requires': ['sysinit.target'],
            'After': ['sysinit.target'],
            'Before': ['sockets.target'],
            'Conflicts': ['shutdown.target'],
        }
    },
    'mount': {
        'DefaultDependencies': {
            'Requires': [],
            'After': ['local-fs-pre.target'],
            'Before': ['local-fs.target', 'umount.target'],
            'Conflicts': ['umount.target'],
        }
    },
    'swap': {
        'DefaultDependencies': {
            'Requires': [],
            'After': ['local-fs-pre.target'],
            'Before': ['swap.target', 'umount.target'],
            'Conflicts': ['umount.target'],
        }
    },
    'timer': {
        'DefaultDependencies': {
            'Requires': ['sysinit.target'],
            'After': ['sysinit.target'],
            'Before': ['timers.target'],
            'Conflicts': ['shutdown.target'],
        }
    },
    'path': {
        'DefaultDependencies': {
            'Requires': ['sysinit.target'],
            'After': ['sysinit.target'],
            'Before': ['paths.target'],
            'Conflicts': ['shutdown.target'],
        }
    },
}

CONDITION_PREFIXES = [
    'ConditionPathExists',
    'ConditionPathIsDirectory',
    'ConditionPathIsSymbolicLink',
    'ConditionPathIsMountPoint',
    'ConditionPathIsReadWrite',
    'ConditionDirectoryNotEmpty',
    'ConditionFileNotEmpty',
    'ConditionFileIsExecutable',
    'ConditionNeedsUpdate',
    'ConditionFirstBoot',
    'ConditionKernelCommandLine',
    'ConditionKernelVersion',
    'ConditionArchitecture',
    'ConditionVirtualization',
    'ConditionHost',
    'ConditionACPower',
    'ConditionSecurity',
    'ConditionCapability',
    'ConditionControlGroupController',
    'ConditionCredential',
    'AssertPathExists',
    'AssertPathIsDirectory',
    'AssertPathIsSymbolicLink',
    'AssertPathIsMountPoint',
    'AssertPathIsReadWrite',
    'AssertDirectoryNotEmpty',
    'AssertFileNotEmpty',
    'AssertFileIsExecutable',
    'AssertNeedsUpdate',
    'AssertFirstBoot',
    'AssertKernelCommandLine',
    'AssertKernelVersion',
    'AssertArchitecture',
    'AssertVirtualization',
    'AssertHost',
    'AssertACPower',
    'AssertSecurity',
    'AssertCapability',
    'AssertControlGroupController',
    'AssertCredential',
]


class SystemdDependencyAnalyzer:
    def __init__(self, target: str = 'multi-user.target'):
        self.target = target
        self.units: Dict[str, Dict] = {}
        self.relationships: List[Tuple[str, str, str]] = []
        self.conditionals: Dict[str, List[Tuple[str, str]]] = {}
        self.unit_paths = [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/run/systemd/system',
            '/usr/local/lib/systemd/system',
            os.path.expanduser('~/.config/systemd/user'),
        ]
        self._all_known_units: Set[str] = set()

    def get_unit_type(self, unit_name: str) -> str:
        if '.' in unit_name:
            return unit_name.split('.')[-1]
        return 'service'

    def is_wildcard(self, dep_name: str) -> bool:
        return '*' in dep_name or '?' in dep_name

    def expand_wildcard(self, wildcard: str) -> List[str]:
        if not self.is_wildcard(wildcard):
            return [wildcard]
        
        pattern = wildcard.replace('.', '\\.').replace('*', '.*').replace('?', '.')
        regex = re.compile(f'^{pattern}$')
        
        matches = []
        for unit in self._all_known_units:
            if regex.match(unit):
                matches.append(unit)
        
        return matches

    def parse_unit_file(self, unit_path: str) -> Dict:
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
            'upheld_by': [],
            'wanted_by': [],
            'required_by': [],
            'upheld_by': [],
            'alias': [],
            'default_dependencies': True,
            'description': '',
        }

        try:
            with open(unit_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError):
            return unit_info

        desc_match = re.search(r'^Description\s*=\s*(.+)$', content, re.MULTILINE)
        if desc_match:
            unit_info['description'] = desc_match.group(1).strip()

        dd_match = re.search(r'^DefaultDependencies\s*=\s*(.+)$', content, re.MULTILINE)
        if dd_match:
            value = dd_match.group(1).strip().lower()
            unit_info['default_dependencies'] = (value in ['yes', 'true', '1'])

        patterns = {
            'requires': r'^Requires\s*=\s*(.+)$',
            'wants': r'^Wants\s*=\s*(.+)$',
            'after': r'^After\s*=\s*(.+)$',
            'before': r'^Before\s*=\s*(.+)$',
            'requisite': r'^Requisite\s*=\s*(.+)$',
            'conflicts': r'^Conflicts\s*=\s*(.+)$',
            'partof': r'^PartOf\s*=\s*(.+)$',
            'binds_to': r'^BindsTo\s*=\s*(.+)$',
            'upheld_by': r'^UpheldBy\s*=\s*(.+)$',
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

        unit_name = unit_info['name']
        self.conditionals[unit_name] = {
            'conditions': [],
            'asserts': [],
        }
        
        for prefix in CONDITION_PREFIXES:
            pattern = rf'^{prefix}\s*=\s*(.+)$'
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                value = match.group(1).strip()
                if prefix.startswith('Assert'):
                    self.conditionals[unit_name]['asserts'].append((prefix, value))
                else:
                    self.conditionals[unit_name]['conditions'].append((prefix, value))

        return unit_info

    def find_unit_file(self, unit_name: str) -> Optional[str]:
        if '.' not in unit_name:
            unit_name = f'{unit_name}.service'

        for path in self.unit_paths:
            if not os.path.exists(path):
                continue
            
            unit_path = os.path.join(path, unit_name)
            if os.path.exists(unit_path):
                return unit_path

            for suffix in ['.wants', '.requires']:
                wants_dir = os.path.join(path, f'{self.target}{suffix}')
                if os.path.exists(wants_dir):
                    unit_path = os.path.join(wants_dir, unit_name)
                    if os.path.exists(unit_path):
                        return os.path.realpath(unit_path)

                multiuser_wants = os.path.join(path, f'multi-user.target{suffix}')
                if os.path.exists(multiuser_wants) and self.target != 'multi-user.target':
                    unit_path = os.path.join(multiuser_wants, unit_name)
                    if os.path.exists(unit_path):
                        return os.path.realpath(unit_path)

        return None

    def get_all_units_from_systemctl(self) -> Set[str]:
        units = set()
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--all', '--no-pager', '--plain'],
                capture_output=True,
                text=True,
                check=False
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    units.add(parts[0])
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['systemctl', 'list-unit-files', '--all', '--no-pager', '--plain'],
                capture_output=True,
                text=True,
                check=False
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    units.add(parts[0])
        except Exception:
            pass

        return units

    def scan_all_wants_requires_dirs(self) -> Dict[str, List[Tuple[str, str]]]:
        all_wants = defaultdict(list)
        
        for path in self.unit_paths:
            if not os.path.exists(path):
                continue
            
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if not os.path.isdir(item_path):
                    continue
                
                if item.endswith('.wants'):
                    target_name = item[:-6]
                    for unit_name in os.listdir(item_path):
                        unit_full_path = os.path.join(item_path, unit_name)
                        if os.path.isdir(unit_full_path):
                            continue
                        all_wants[target_name].append((unit_name, 'Wants'))
                
                elif item.endswith('.requires'):
                    target_name = item[:-9]
                    for unit_name in os.listdir(item_path):
                        unit_full_path = os.path.join(item_path, unit_name)
                        if os.path.isdir(unit_full_path):
                            continue
                        all_wants[target_name].append((unit_name, 'Requires'))

        return dict(all_wants)

    def add_default_dependencies(self, unit_name: str, unit_info: Dict):
        if not unit_info['default_dependencies']:
            return
        
        unit_type = unit_info['type']
        if unit_type not in DEFAULT_DEPENDENCIES:
            return
        
        defaults = DEFAULT_DEPENDENCIES[unit_type]['DefaultDependencies']
        
        for rel_type, deps in defaults.items():
            for dep in deps:
                rel_list = rel_type.lower().replace(' ', '_')
                if hasattr(unit_info, rel_list):
                    if dep not in unit_info[rel_list]:
                        unit_info[rel_list].append(dep)
                elif rel_list == 'requires' and dep not in unit_info['requires']:
                    unit_info['requires'].append(dep)
                elif rel_list == 'after' and dep not in unit_info['after']:
                    unit_info['after'].append(dep)
                elif rel_list == 'before' and dep not in unit_info['before']:
                    unit_info['before'].append(dep)
                elif rel_list == 'conflicts' and dep not in unit_info['conflicts']:
                    unit_info['conflicts'].append(dep)

    def process_unit(self, unit_name: str, visited: Set[str], queue: List[str]):
        if unit_name in visited:
            return

        visited.add(unit_name)

        unit_path = self.find_unit_file(unit_name)

        if not unit_path and unit_name in self._all_known_units:
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
            self.add_default_dependencies(unit_name, unit_info)
            self.units[unit_name] = unit_info

            for alias in unit_info['alias']:
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
                        'upheld_by': [],
                        'wanted_by': [],
                        'required_by': [],
                        'alias': [],
                        'default_dependencies': True,
                        'description': f'Alias for {unit_name}',
                    }
                self.relationships.append((alias, unit_name, 'Alias'))
                if alias not in visited:
                    queue.append(alias)

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
            for dep in unit_info['upheld_by']:
                deps.append((dep, 'UpheldBy'))

            for dep_name, rel_type in deps:
                expanded_deps = self.expand_wildcard(dep_name)
                for expanded_dep in expanded_deps:
                    self.relationships.append((unit_name, expanded_dep, rel_type))
                    if expanded_dep not in visited:
                        queue.append(expanded_dep)

            for wanted_by in unit_info['wanted_by']:
                self.relationships.append((wanted_by, unit_name, 'Wants'))
                if wanted_by not in visited:
                    queue.append(wanted_by)

            for required_by in unit_info['required_by']:
                self.relationships.append((required_by, unit_name, 'Requires'))
                if required_by not in visited:
                    queue.append(required_by)
        else:
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
                'upheld_by': [],
                'wanted_by': [],
                'required_by': [],
                'alias': [],
                'default_dependencies': True,
                'description': 'Unit file not found',
            }

    def remove_duplicates_and_placeholders(self):
        seen = set()
        unique_relationships = []
        
        for source, target, rel_type in self.relationships:
            key = (source, target, rel_type)
            if key not in seen:
                seen.add(key)
                unique_relationships.append((source, target, rel_type))
        
        self.relationships = unique_relationships

        units_with_file = set()
        for unit_name, unit_info in self.units.items():
            if unit_info['path'] is not None:
                units_with_file.add(unit_name)

        for unit_name in list(self.units.keys()):
            unit_info = self.units[unit_name]
            if unit_info['path'] is None:
                del self.units[unit_name]

        final_relationships = []
        for source, target, rel_type in self.relationships:
            if source in self.units and target in self.units:
                final_relationships.append((source, target, rel_type))
        
        self.relationships = final_relationships

    def build_dependency_graph(self):
        visited = set()
        queue = [self.target]

        self._all_known_units = self.get_all_units_from_systemctl()

        for path in self.unit_paths:
            if os.path.exists(path):
                for item in os.listdir(path):
                    if '.' in item and not item.startswith('.'):
                        self._all_known_units.add(item)

        all_wants_requires = self.scan_all_wants_requires_dirs()
        
        for target_name, deps in all_wants_requires.items():
            for unit_name, rel_type in deps:
                if target_name == self.target:
                    if unit_name not in visited:
                        queue.append(unit_name)

        while queue:
            unit_name = queue.pop(0)
            self.process_unit(unit_name, visited, queue)

        for target_name, deps in all_wants_requires.items():
            for unit_name, rel_type in deps:
                if target_name in self.units and unit_name in self.units:
                    self.relationships.append((target_name, unit_name, rel_type))

        self.remove_duplicates_and_placeholders()

    def generate_dot(self) -> str:
        dot_lines = [
            'digraph systemd_dependencies {',
            '    rankdir=LR;',
            '    compound=true;',
            '    node [fontname="Arial", fontsize=10, style="filled,solid", shape="box", penwidth=1.5];',
            '    edge [fontname="Arial", fontsize=8, arrowhead=open];',
        ]

        target_subgraphs = defaultdict(list)
        for unit_name, unit_info in self.units.items():
            unit_type = unit_info['type']
            target_subgraphs[unit_type].append(unit_name)

        type_order = ['target', 'service', 'socket', 'mount', 'path', 'timer', 'swap', 'slice', 'scope']
        all_types = list(target_subgraphs.keys())
        sorted_types = [t for t in type_order if t in all_types]
        for t in all_types:
            if t not in sorted_types:
                sorted_types.append(t)

        for unit_type in sorted_types:
            unit_names = sorted(target_subgraphs[unit_type])
            if not unit_names:
                continue
            
            dot_lines.append(f'')
            dot_lines.append(f'    subgraph cluster_{unit_type} {{')
            dot_lines.append(f'        label="{unit_type} units";')
            dot_lines.append(f'        style="dashed";')
            dot_lines.append(f'        color="#CCCCCC";')
            dot_lines.append(f'        bgcolor="#FAFAFA";')
            
            for unit_name in unit_names:
                unit_info = self.units[unit_name]
                color = UNIT_COLORS.get(unit_type, '#808080')
                description = unit_info['description'].replace('"', '\\"').replace('\n', ' ')
                
                cond_data = self.conditionals.get(unit_name, {})
                has_conditions = len(cond_data.get('conditions', [])) > 0
                has_asserts = len(cond_data.get('asserts', [])) > 0
                
                condition_note = ''
                if has_asserts:
                    condition_note = ' [ASSERT]'
                elif has_conditions:
                    condition_note = ' [COND]'
                
                label = f'{unit_name}{condition_note}\\n{description[:40]}{"..." if len(description) > 40 else ""}'
                
                if has_asserts:
                    dot_lines.append(f'        "{unit_name}" [label="{label}", fillcolor="{color}", color="#FF0000", penwidth=3, style="filled,dashed"];')
                elif has_conditions:
                    dot_lines.append(f'        "{unit_name}" [label="{label}", fillcolor="{color}", color="#FF6600", penwidth=2, style="filled,dashed"];')
                else:
                    dot_lines.append(f'        "{unit_name}" [label="{label}", fillcolor="{color}", color="{color}"];')
            
            dot_lines.append(f'    }}')

        dot_lines.append('')

        for source, target, rel_type in self.relationships:
            color = RELATION_COLORS.get(rel_type, '#808080')
            style = 'solid' if rel_type in ['Requires', 'Requisite', 'BindsTo'] else 'dashed'
            width = '2' if rel_type in ['Requires', 'Requisite'] else '1'
            
            dot_lines.append(
                f'    "{source}" -> "{target}" [label="{rel_type}", color="{color}", style="{style}", penwidth={width}];'
            )

        dot_lines.extend([
            '',
            '    {',
            '        rank=min;',
            '        subgraph cluster_legend_left {',
            '            label="Unit Types";',
            '            style="filled";',
            '            color="#F0F0F0";',
            '            style="dashed";',
        ])

        for i, (unit_type, color) in enumerate(UNIT_COLORS.items()):
            if unit_type in target_subgraphs:
                dot_lines.append(f'            legend_unit_{i} [label="{unit_type}", fillcolor="{color}", style="filled", shape="box"];')

        dot_lines.extend([
            '        }',
            '    }',
            '',
            '    {',
            '        rank=max;',
            '        subgraph cluster_legend_right {',
            '            label="Relationships & Conditions";',
            '            style="filled";',
            '            color="#F0F0F0";',
            '            style="dashed";',
        ])

        for i, (rel_type, color) in enumerate(RELATION_COLORS.items()):
            style = 'solid' if rel_type in ['Requires', 'Requisite', 'BindsTo'] else 'dashed'
            dot_lines.append(f'            legend_rel_{i} [label="{rel_type}", style="dotted", shape="plaintext"];')

        dot_lines.append('            legend_cond [label="[COND] = Condition (optional)", style="dashed", shape="box", color="#FF6600"];')
        dot_lines.append('            legend_assert [label="[ASSERT] = Assert (required/fail)", style="dashed", shape="box", color="#FF0000"];')
        dot_lines.append('        }')
        dot_lines.append('    }')
        dot_lines.append('}')

        return '\n'.join(dot_lines)

    def generate_html(self) -> str:
        sorted_units = sorted(self.units.keys())
        
        nodes_data = []
        for unit_name in sorted_units:
            unit_info = self.units[unit_name]
            cond_data = self.conditionals.get(unit_name, {})
            has_conditions = len(cond_data.get('conditions', [])) > 0
            has_asserts = len(cond_data.get('asserts', [])) > 0
            
            all_conditions = []
            for cond in cond_data.get('conditions', []):
                all_conditions.append({'type': cond[0], 'value': cond[1], 'category': 'Condition'})
            for cond in cond_data.get('asserts', []):
                all_conditions.append({'type': cond[0], 'value': cond[1], 'category': 'Assert'})
            
            border_color = UNIT_COLORS.get(unit_info['type'], '#808080')
            if has_asserts:
                border_color = '#FF0000'
            elif has_conditions:
                border_color = '#FF6600'
            
            nodes_data.append({
                'id': unit_name,
                'type': unit_info['type'],
                'description': unit_info['description'],
                'color': UNIT_COLORS.get(unit_info['type'], '#808080'),
                'borderColor': border_color,
                'hasConditions': has_conditions,
                'hasAsserts': has_asserts,
                'conditions': all_conditions,
            })

        links_data = []
        for source, target, rel_type in self.relationships:
            links_data.append({
                'source': source,
                'target': target,
                'type': rel_type,
                'color': RELATION_COLORS.get(rel_type, '#808080')
            })

        unit_types_js = str({k: v for k, v in UNIT_COLORS.items()}).replace("'", '"')
        rel_types_js = str({k: v for k, v in RELATION_COLORS.items()}).replace("'", '"')

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Systemd Dependency Graph - {self.target}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 100%;
            margin: 0 auto;
            padding: 20px;
        }}
        h1 {{
            color: white;
            text-align: center;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .search-bar {{
            text-align: center;
            margin-bottom: 20px;
        }}
        .search-bar input {{
            width: 300px;
            padding: 12px 20px;
            border: none;
            border-radius: 25px;
            font-size: 14px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            outline: none;
        }}
        .search-bar input:focus {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }}
        .controls {{
            text-align: center;
            margin-bottom: 15px;
        }}
        .controls button {{
            padding: 8px 16px;
            margin: 0 5px;
            background: rgba(255,255,255,0.9);
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.3s ease;
        }}
        .controls button:hover {{
            background: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        #graph-container {{
            width: 100%;
            height: 700px;
            border: none;
            border-radius: 15px;
            background: white;
            position: relative;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .node rect {{
            rx: 6;
            ry: 6;
            stroke-width: 2;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        .node:hover rect {{
            filter: brightness(1.1);
            stroke-width: 3;
        }}
        .node.highlighted rect {{
            stroke: #FF6600 !important;
            stroke-width: 4;
            filter: drop-shadow(0 0 8px #FF6600);
        }}
        .node text {{
            font-size: 11px;
            pointer-events: none;
            font-weight: 500;
        }}
        .link {{
            fill: none;
            stroke-width: 1.5;
            opacity: 0.7;
            transition: all 0.3s ease;
        }}
        .link:hover {{
            stroke-width: 3;
            opacity: 1;
        }}
        .link.highlighted {{
            stroke: #FF6600 !important;
            stroke-width: 3;
            opacity: 1;
        }}
        .link-label {{
            font-size: 9px;
            fill: #666;
            font-weight: 500;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 15px;
            border-radius: 10px;
            font-size: 13px;
            pointer-events: none;
            z-index: 1000;
            max-width: 350px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .tooltip h4 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #FFD700;
        }}
        .tooltip .conditions {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.3);
        }}
        .tooltip .condition-item {{
            font-size: 11px;
            color: #FF9999;
            margin: 3px 0;
        }}
        .legend {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255, 255, 255, 0.95);
            padding: 15px;
            border-radius: 10px;
            font-size: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            max-height: 300px;
            overflow-y: auto;
        }}
        .legend h3 {{
            margin-top: 0;
            margin-bottom: 10px;
            font-size: 13px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }}
        .legend-item {{
            margin-bottom: 6px;
            display: flex;
            align-items: center;
        }}
        .legend-color {{
            display: inline-block;
            width: 14px;
            height: 14px;
            margin-right: 8px;
            border-radius: 3px;
        }}
        .legend-line {{
            display: inline-block;
            width: 24px;
            height: 2px;
            margin-right: 8px;
        }}
        .legend-cond {{
            border: 2px dashed #FF6600;
            background: transparent;
        }}
        .stats {{
            text-align: center;
            color: white;
            margin-top: 15px;
            font-size: 14px;
            opacity: 0.9;
        }}
        .search-results {{
            position: absolute;
            top: 120px;
            left: 50%;
            transform: translateX(-50%);
            background: white;
            border-radius: 10px;
            padding: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            z-index: 100;
            display: none;
            max-width: 400px;
            max-height: 200px;
            overflow-y: auto;
        }}
        .search-results.visible {{
            display: block;
        }}
        .search-result-item {{
            padding: 8px 12px;
            cursor: pointer;
            border-radius: 5px;
            transition: background 0.2s ease;
        }}
        .search-result-item:hover {{
            background: #f0f0f0;
        }}
        .nav-buttons {{
            position: absolute;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            display: none;
            gap: 10px;
        }}
        .nav-buttons.visible {{
            display: flex;
        }}
        .nav-buttons button {{
            padding: 6px 12px;
            background: rgba(255,255,255,0.9);
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }}
        .match-count {{
            position: absolute;
            top: 80px;
            right: 20px;
            background: #FF6600;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            display: none;
        }}
        .match-count.visible {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Systemd Dependency Graph - {self.target}</h1>
        
        <div class="search-bar">
            <input type="text" id="search-input" placeholder="Search for unit (e.g., sshd, network, multi-user)...">
        </div>
        
        <div class="nav-buttons" id="nav-buttons">
            <button id="prev-match">◀ Previous</button>
            <button id="next-match">Next ▶</button>
            <button id="clear-search">✕ Clear</button>
        </div>
        
        <div class="match-count" id="match-count"></div>
        
        <div class="search-results" id="search-results"></div>
        
        <div class="controls">
            <button id="zoom-in">🔍 Zoom In</button>
            <button id="zoom-out">🔍 Zoom Out</button>
            <button id="reset-zoom">↩ Reset</button>
            <button id="fit-view">⬜ Fit View</button>
        </div>
        
        <div id="graph-container">
            <div class="legend">
                <h3>Unit Types</h3>
'''

        for unit_type, color in UNIT_COLORS.items():
            html += f'                <div class="legend-item"><span class="legend-color" style="background-color: {color};"></span>{unit_type}</div>\n'

        html += '''                <div class="legend-item"><span class="legend-color legend-cond"></span>Has conditions</div>
                <h3>Relationships</h3>
'''

        for rel_type, color in RELATION_COLORS.items():
            style = 'solid' if rel_type in ['Requires', 'Requisite', 'BindsTo'] else 'dashed'
            html += f'                <div class="legend-item"><span class="legend-line" style="border-bottom: 2px {style} {color};"></span>{rel_type}</div>\n'

        html += '''            </div>
            <div class="tooltip" id="tooltip"></div>
        </div>
        
        <div class="stats" id="stats"></div>
    </div>

    <script>
        const nodes = ''' + str(nodes_data).replace("'", '"') + ''';
        const links = ''' + str(links_data).replace("'", '"') + ''';
        const unitTypes = ''' + unit_types_js + ''';
        const relationTypes = ''' + rel_types_js + ''';

        let currentMatchIndex = -1;
        let matchedNodes = [];

        const container = document.getElementById('graph-container');
        const width = container.clientWidth;
        const height = container.clientHeight;

        const svg = d3.select('#graph-container')
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        const g = svg.append('g');

        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);

        document.getElementById('zoom-in').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.scaleBy, 1.3);
        });

        document.getElementById('zoom-out').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.scaleBy, 0.7);
        });

        document.getElementById('reset-zoom').addEventListener('click', () => {
            svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);
        });

        document.getElementById('fit-view').addEventListener('click', () => {
            const bounds = g.node().getBBox();
            const fullWidth = bounds.width || 100;
            const fullHeight = bounds.height || 100;
            const midX = bounds.x + fullWidth / 2;
            const midY = bounds.y + fullHeight / 2;
            const scale = Math.min(width / fullWidth, height / fullHeight) * 0.9;
            const translate = [width / 2 - scale * midX, height / 2 - scale * midY];
            
            svg.transition().duration(500).call(
                zoom.transform,
                d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
            );
        });

        const tooltip = d3.select('#tooltip');

        const nodeMap = new Map();
        nodes.forEach((n, i) => {
            nodeMap.set(n.id, i);
        });

        const linksProcessed = links.map(l => ({
            source: nodeMap.get(l.source),
            target: nodeMap.get(l.target),
            type: l.type,
            color: l.color
        }));

        const typeGroups = {};
        nodes.forEach((n, i) => {
            if (!typeGroups[n.type]) typeGroups[n.type] = [];
            typeGroups[n.type].push(i);
        });

        for (const type in typeGroups) {
            typeGroups[type].sort((a, b) => nodes[a].id.localeCompare(nodes[b].id));
        }

        const typeOrder = ['target', 'service', 'socket', 'mount', 'path', 'timer', 'swap', 'slice', 'scope'];
        const nodeX = {};
        const nodeY = {};
        let maxX = 0;

        typeOrder.forEach((type, col) => {
            const indices = typeGroups[type] || [];
            const x = col * 200 + 100;
            maxX = Math.max(maxX, x);
            
            indices.forEach((i, row) => {
                const y = row * 80 + 80;
                nodeX[nodes[i].id] = x;
                nodeY[nodes[i].id] = y;
                nodes[i].x = x;
                nodes[i].y = y;
            });
        });

        const remainingTypes = Object.keys(typeGroups).filter(t => !typeOrder.includes(t));
        remainingTypes.sort();
        let nextCol = typeOrder.length;
        remainingTypes.forEach((type) => {
            const indices = typeGroups[type] || [];
            const x = nextCol * 200 + 100;
            maxX = Math.max(maxX, x);
            
            indices.forEach((i, row) => {
                const y = row * 80 + 80;
                nodeX[nodes[i].id] = x;
                nodeY[nodes[i].id] = y;
                nodes[i].x = x;
                nodes[i].y = y;
            });
            nextCol++;
        });

        const link = g.append('g')
            .selectAll('path')
            .data(linksProcessed)
            .join('path')
            .attr('class', 'link')
            .attr('stroke', d => d.color)
            .attr('stroke-dasharray', d => d.type === 'Wants' || d.type === 'After' || d.type === 'Before' ? '5,3' : null)
            .attr('fill', 'none');

        const linkLabel = g.append('g')
            .selectAll('text')
            .data(linksProcessed)
            .join('text')
            .attr('class', 'link-label')
            .text(d => d.type);

        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .join('g')
            .attr('class', 'node')
            .attr('id', d => `node-${d.id.replace(/[\\./]/g, '-')}`)
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        node.append('rect')
            .attr('width', d => Math.max(d.id.length * 8 + 16, 80))
            .attr('height', 36)
            .attr('fill', d => d.color)
            .attr('stroke', d => d.borderColor)
            .attr('stroke-dasharray', d => (d.hasConditions || d.hasAsserts) ? '4,2' : null)
            .attr('stroke-width', d => d.hasAsserts ? 3 : (d.hasConditions ? 2 : 1.5))
            .attr('rx', 6)
            .attr('ry', 6);

        node.append('text')
            .attr('x', d => Math.max(d.id.length * 8 + 16, 80) / 2)
            .attr('y', 22)
            .attr('text-anchor', 'middle')
            .attr('fill', 'white')
            .text(d => d.id.length > 18 ? d.id.substring(0, 16) + '..' : d.id);

        node.on('mouseover', function(event, d) {
            let tooltipHtml = `<h4>${d.id}</h4>`;
            tooltipHtml += `<strong>Type:</strong> ${d.type}<br>`;
            tooltipHtml += `<strong>Description:</strong> ${d.description || 'N/A'}`;
            
            if (d.conditions && d.conditions.length > 0) {
                const assertConditions = d.conditions.filter(c => c.category === 'Assert');
                const regularConditions = d.conditions.filter(c => c.category === 'Condition');
                
                if (assertConditions.length > 0) {
                    tooltipHtml += '<div class="conditions"><strong style="color: #FF6666;">Asserts (required/fail):</strong><br>';
                    assertConditions.forEach(c => {
                        tooltipHtml += `<div class="condition-item" style="color: #FF6666;">${c.type} = ${c.value}</div>`;
                    });
                    tooltipHtml += '</div>';
                }
                
                if (regularConditions.length > 0) {
                    tooltipHtml += '<div class="conditions"><strong style="color: #FFCC66;">Conditions (optional):</strong><br>';
                    regularConditions.forEach(c => {
                        tooltipHtml += `<div class="condition-item" style="color: #FFCC66;">${c.type} = ${c.value}</div>`;
                    });
                    tooltipHtml += '</div>';
                }
            }
            
            const incoming = links.filter(l => l.target === d.id);
            const outgoing = links.filter(l => l.source === d.id);
            
            if (incoming.length > 0 || outgoing.length > 0) {
                tooltipHtml += '<div class="conditions" style="border-top: 1px solid rgba(255,255,255,0.3); padding-top: 8px;">';
                
                if (incoming.length > 0) {
                    tooltipHtml += '<strong>Incoming:</strong><br>';
                    incoming.slice(0, 5).forEach(l => {
                        tooltipHtml += `<span style="color: #99CCFF;">${l.source}</span> → <span style="color: #FFD700;">${l.type}</span><br>`;
                    });
                    if (incoming.length > 5) {
                        tooltipHtml += `<span style="color: #999;">...and ${incoming.length - 5} more</span><br>`;
                    }
                }
                
                if (outgoing.length > 0) {
                    tooltipHtml += '<br><strong>Outgoing:</strong><br>';
                    outgoing.slice(0, 5).forEach(l => {
                        tooltipHtml += `<span style="color: #FFD700;">${l.type}</span> → <span style="color: #99CCFF;">${l.target}</span><br>`;
                    });
                    if (outgoing.length > 5) {
                        tooltipHtml += `<span style="color: #999;">...and ${outgoing.length - 5} more</span><br>`;
                    }
                }
                
                tooltipHtml += '</div>';
            }
            
            tooltip
                .style('display', 'block')
                .style('left', (event.pageX + 15) + 'px')
                .style('top', (event.pageY - 15) + 'px')
                .html(tooltipHtml);

            const relatedNodes = new Set([d.id]);
            linksProcessed.forEach(l => {
                if (nodes[l.source].id === d.id || nodes[l.target].id === d.id) {
                    relatedNodes.add(nodes[l.source].id);
                    relatedNodes.add(nodes[l.target].id);
                }
            });
            
            node.classed('dimmed', n => !relatedNodes.has(n.id));
            link.classed('dimmed', l => nodes[l.source].id !== d.id && nodes[l.target].id !== d.id);
        })
        .on('mousemove', (event) => {
            tooltip
                .style('left', (event.pageX + 15) + 'px')
                .style('top', (event.pageY - 15) + 'px');
        })
        .on('mouseout', () => {
            tooltip.style('display', 'none');
            node.classed('dimmed', false);
            link.classed('dimmed', false);
        });

        function updateLinks() {
            link.attr('d', d => {
                const sx = nodes[d.source].x;
                const sy = nodes[d.source].y;
                const tx = nodes[d.target].x;
                const ty = nodes[d.target].y;
                
                const dx = tx - sx;
                const dy = ty - sy;
                
                if (Math.abs(dx) > Math.abs(dy)) {
                    const mx = (sx + tx) / 2;
                    return `M${sx},${sy} C${mx},${sy} ${mx},${ty} ${tx},${ty}`;
                } else {
                    const my = (sy + ty) / 2;
                    return `M${sx},${sy} C${sx},${my} ${tx},${my} ${tx},${ty}`;
                }
            });

            linkLabel.attr('transform', d => {
                const sx = nodes[d.source].x;
                const sy = nodes[d.source].y;
                const tx = nodes[d.target].x;
                const ty = nodes[d.target].y;
                const mx = (sx + tx) / 2;
                const my = (sy + ty) / 2;
                return `translate(${mx},${my})`;
            });
        }

        function updateNodes() {
            node.attr('transform', d => `translate(${d.x - Math.max(d.id.length * 8 + 16, 80) / 2}, ${d.y - 18})`);
        }

        updateLinks();
        updateNodes();

        function dragstarted(event) {
            if (!event.active) {
            }
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
            event.subject.x = event.x;
            event.subject.y = event.y;
            updateLinks();
            updateNodes();
        }

        function dragended(event) {
            if (!event.active) {
            }
            event.subject.fx = null;
            event.subject.fy = null;
        }

        const searchInput = document.getElementById('search-input');
        const searchResults = document.getElementById('search-results');
        const navButtons = document.getElementById('nav-buttons');
        const matchCount = document.getElementById('match-count');

        function clearHighlights() {
            node.classed('highlighted', false);
            link.classed('highlighted', false);
            currentMatchIndex = -1;
            matchedNodes = [];
            navButtons.classList.remove('visible');
            matchCount.classList.remove('visible');
            searchResults.classList.remove('visible');
        }

        function highlightNode(unitId) {
            clearHighlights();
            
            const targetNode = node.filter(n => n.id === unitId);
            targetNode.classed('highlighted', true);
            
            const relatedLinks = linksProcessed.filter(l => 
                nodes[l.source].id === unitId || nodes[l.target].id === unitId
            );
            
            link.filter((d, i) => relatedLinks.includes(linksProcessed[i]))
                .classed('highlighted', true);
            
            const relatedNodeIds = new Set([unitId]);
            relatedLinks.forEach(l => {
                relatedNodeIds.add(nodes[l.source].id);
                relatedNodeIds.add(nodes[l.target].id);
            });
            
            const targetData = nodes.find(n => n.id === unitId);
            if (targetData) {
                const cx = targetData.x;
                const cy = targetData.y;
                const scale = 1.5;
                const tx = width / 2 - scale * cx;
                const ty = height / 2 - scale * cy;
                
                svg.transition().duration(500).call(
                    zoom.transform,
                    d3.zoomIdentity.translate(tx, ty).scale(scale)
                );
            }
        }

        function performSearch(query) {
            if (!query || query.trim() === '') {
                clearHighlights();
                return;
            }
            
            const q = query.toLowerCase().trim();
            matchedNodes = nodes.filter(n => 
                n.id.toLowerCase().includes(q) || 
                n.description.toLowerCase().includes(q) ||
                n.type.toLowerCase().includes(q)
            );
            
            if (matchedNodes.length === 0) {
                clearHighlights();
                matchCount.textContent = 'No matches';
                matchCount.classList.add('visible');
                return;
            }
            
            matchCount.textContent = `${matchedNodes.length} match${matchedNodes.length > 1 ? 'es' : ''}`;
            matchCount.classList.add('visible');
            
            if (matchedNodes.length === 1) {
                highlightNode(matchedNodes[0].id);
            } else {
                searchResults.innerHTML = '';
                matchedNodes.forEach((n, i) => {
                    const item = document.createElement('div');
                    item.className = 'search-result-item';
                    item.innerHTML = `<strong>${n.id}</strong><br><small>${n.description || ''}</small>`;
                    item.onclick = () => {
                        highlightNode(n.id);
                        searchResults.classList.remove('visible');
                    };
                    searchResults.appendChild(item);
                });
                searchResults.classList.add('visible');
                
                navButtons.classList.add('visible');
                currentMatchIndex = 0;
                highlightNode(matchedNodes[0].id);
            }
        }

        searchInput.addEventListener('input', (e) => {
            performSearch(e.target.value);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                clearHighlights();
                searchInput.value = '';
            } else if (e.key === 'Enter' && matchedNodes.length > 0) {
                searchResults.classList.remove('visible');
            }
        });

        document.getElementById('prev-match').addEventListener('click', () => {
            if (matchedNodes.length === 0) return;
            currentMatchIndex = (currentMatchIndex - 1 + matchedNodes.length) % matchedNodes.length;
            highlightNode(matchedNodes[currentMatchIndex].id);
            matchCount.textContent = `${currentMatchIndex + 1}/${matchedNodes.length}`;
        });

        document.getElementById('next-match').addEventListener('click', () => {
            if (matchedNodes.length === 0) return;
            currentMatchIndex = (currentMatchIndex + 1) % matchedNodes.length;
            highlightNode(matchedNodes[currentMatchIndex].id);
            matchCount.textContent = `${currentMatchIndex + 1}/${matchedNodes.length}`;
        });

        document.getElementById('clear-search').addEventListener('click', () => {
            clearHighlights();
            searchInput.value = '';
        });

        document.addEventListener('click', (e) => {
            if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
                searchResults.classList.remove('visible');
            }
        });

        document.getElementById('stats').textContent = 
            `Total: ${nodes.length} units | ${links.length} relationships | Target: {self.target}`;

        setTimeout(() => {
            document.getElementById('fit-view').click();
        }, 100);
    </script>
</body>
</html>
'''
        return html

    def save_output(self, output_format: str, output_path: str):
        if output_format == 'dot':
            content = self.generate_dot()
        elif output_format == 'html':
            content = self.generate_html()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"Graph saved to: {output_path}")

    def get_validation_data(self) -> Dict:
        validation = {
            'units': list(self.units.keys()),
            'relationships': [],
            'conditionals': self.conditionals,
        }
        
        for source, target, rel_type in self.relationships:
            validation['relationships'].append({
                'source': source,
                'target': target,
                'type': rel_type
            })
        
        return validation


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
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Generate validation data for comparison with systemctl'
    )

    args = parser.parse_args()

    if not args.output:
        args.output = f'systemd_deps.{args.format}'

    analyzer = SystemdDependencyAnalyzer(target=args.target)
    
    if args.verbose:
        print(f"Analyzing dependencies for target: {args.target}")
        print("Building dependency graph...")
    
    analyzer.build_dependency_graph()
    
    if args.verbose:
        print(f"Found {len(analyzer.units)} units")
        print(f"Found {len(analyzer.relationships)} relationships")
        
        cond_count = sum(1 for v in analyzer.conditionals.values() if len(v) > 0)
        print(f"Units with conditions: {cond_count}")
        
        for service_name in ['sshd.service', 'ssh.service', 'network.target']:
            if service_name in analyzer.units:
                print(f"\n{service_name} found!")
                info = analyzer.units[service_name]
                print(f"  Type: {info['type']}")
                print(f"  Description: {info['description']}")
        
        print("\n--- Checking relationships involving ssh/sshd ---")
        for source, target, rel_type in analyzer.relationships:
            if 'ssh' in source.lower() or 'ssh' in target.lower():
                print(f"  {source} -> {target} ({rel_type})")

    if args.validate:
        import json
        validation_data = analyzer.get_validation_data()
        val_path = args.output.replace(f'.{args.format}', '_validation.json')
        with open(val_path, 'w', encoding='utf-8') as f:
            json.dump(validation_data, f, indent=2)
        print(f"Validation data saved to: {val_path}")

    analyzer.save_output(args.format, args.output)

    print("\nAnalysis complete!")
    if args.format == 'html':
        print("Features:")
        print("  - Hierarchical (column) layout by unit type")
        print("  - Search and highlight functionality")
        print("  - Navigation between search results")
        print("  - Conditional units marked with [COND]")
        print("  - Interactive tooltips showing conditions")
    elif args.format == 'dot':
        print("Features:")
        print("  - Units grouped by type in subgraphs")
        print("  - Conditional units marked with dashed borders")
        print("  - Different line styles for different relationship types")
        print("\nTo convert to image:")
        print(f"  dot -Tpng {args.output} -o systemd_deps.png")
        print(f"  dot -Tsvg {args.output} -o systemd_deps.svg")


if __name__ == '__main__':
    main()
