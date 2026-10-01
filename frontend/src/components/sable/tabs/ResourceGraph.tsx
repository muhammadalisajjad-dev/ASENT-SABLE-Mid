import React, { useEffect, useRef } from 'react';
import { SableRunState } from '../types';
import { Network } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

type NodeType = 'aws_s3_bucket' | 'aws_iam_role' | 'aws_iam_role_policy' | 'aws_s3_bucket_policy' | 'aws_iam_policy' | 'module' | string;

const NODE_COLORS: Record<NodeType, string> = {
  aws_s3_bucket: '#2563eb',
  aws_iam_role: '#7c3aed',
  aws_iam_role_policy: '#059669',
  aws_s3_bucket_policy: '#0891b2',
  aws_iam_policy: '#ea580c',
  module: '#6b7280',
};

const EDGE_COLORS: Record<string, string> = {
  references: '#94a3b8',
  attaches: '#7c3aed',
  grants: '#059669',
  obligation: '#dc2626',
};

interface GraphNode { id: string; type: string; x?: number; y?: number; }
interface GraphEdge { source: string; target: string; relation: string; }

function layoutNodes(nodes: GraphNode[], width: number, height: number): GraphNode[] {
  const n = nodes.length;
  if (n === 0) return [];
  const cx = width / 2, cy = height / 2, r = Math.min(width, height) * 0.35;
  return nodes.map((node, i) => ({
    ...node,
    x: cx + r * Math.cos((2 * Math.PI * i) / n),
    y: cy + r * Math.sin((2 * Math.PI * i) / n),
  }));
}

function GraphCanvas({ graph, title, obligationPrincipal, obligationAsset, successor }:
  { graph: { nodes: any[]; edges: any[] } | null; title: string; obligationPrincipal?: string; obligationAsset?: string; successor?: string | null }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const W = 420, H = 280;

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="sable-graph-empty">
        <Network size={24} strokeWidth={1.2}/>
        <p>{title} — no data</p>
      </div>
    );
  }

  const nodes = layoutNodes(graph.nodes.map((n: any) => ({ id: n.id, type: n.type })), W, H);
  const nodeMap: Record<string, GraphNode> = {};
  nodes.forEach(n => { nodeMap[n.id] = n; });

  return (
    <div className="sable-graph-wrap">
      <div className="sable-graph-title">{title}</div>
      <svg ref={svgRef} width={W} height={H} className="sable-resource-svg">
        <defs>
          {Object.entries(EDGE_COLORS).map(([rel, color]) => (
            <marker key={rel} id={`arrow-${rel}`} viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={color}/>
            </marker>
          ))}
        </defs>

        {/* Edges */}
        {graph.edges.map((e: any, i: number) => {
          const src = nodeMap[e.source], tgt = nodeMap[e.target];
          if (!src || !tgt) return null;
          const isObligation = e.source === obligationPrincipal && e.target === obligationAsset;
          const color = isObligation ? EDGE_COLORS.obligation : (EDGE_COLORS[e.relation] ?? EDGE_COLORS.references);
          const rel = isObligation ? 'obligation' : (e.relation ?? 'references');
          return (
            <line key={i}
              x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
              stroke={color} strokeWidth={isObligation ? 2.5 : 1.5}
              strokeDasharray={isObligation ? '6 3' : undefined}
              markerEnd={`url(#arrow-${rel})`}
              opacity={0.7}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map((node) => {
          const isOblAsset = node.id === obligationAsset;
          const isOblPrinc = node.id === obligationPrincipal;
          const isSuccessor = node.id === successor;
          const color = NODE_COLORS[node.type] ?? '#6b7280';
          const r = isOblAsset || isOblPrinc ? 22 : 16;
          return (
            <g key={node.id} transform={`translate(${node.x},${node.y})`}>
              <circle r={r} fill={color} opacity={0.15} stroke={color}
                strokeWidth={isSuccessor ? 3 : isOblAsset || isOblPrinc ? 2 : 1.5}
                strokeDasharray={isSuccessor ? '5 3' : undefined}
              />
              <text textAnchor="middle" dy="4" fontSize="8" fill={color} fontWeight="600">
                {node.id.split('.').pop()?.slice(0, 12)}
              </text>
              <text textAnchor="middle" dy="14" fontSize="6" fill="#64748b">
                {node.type?.replace('aws_', '').slice(0, 14)}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="sable-graph-legend">
        {Object.entries(NODE_COLORS).slice(0, 4).map(([type, color]) => (
          <span key={type} className="sable-legend-item">
            <span className="sable-legend-dot" style={{ background: color }}/>
            {type.replace('aws_', '')}
          </span>
        ))}
        <span className="sable-legend-item">
          <span className="sable-legend-line" style={{ borderColor: EDGE_COLORS.obligation }}/>
          obligation
        </span>
      </div>
    </div>
  );
}

export const ResourceGraphTab: React.FC<Props> = ({ runState, explainSimply }) => {
  if (!runState.baselineGraph && !runState.candidateGraph) {
    return (
      <div className="sable-tab-empty">
        <Network size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see the resource graphs.</p>
      </div>
    );
  }

  return (
    <div className="sable-tab-content">
      <p className="sable-graph-note">
        Solid circles = baseline obligation assets. Dashed border = identified successor.
        Red dashed edge = obligation relationship (principal → protected asset).
      </p>
      <div className="sable-graphs-row">
        <GraphCanvas
          graph={runState.baselineGraph}
          title="Baseline"
          obligationPrincipal={runState.obligation?.principal}
          obligationAsset={runState.obligation?.protected_asset}
        />
        <GraphCanvas
          graph={runState.candidateGraph}
          title="Candidate"
          obligationPrincipal={runState.obligation?.principal}
          obligationAsset={runState.obligation?.protected_asset}
          successor={runState.successor}
        />
      </div>
      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> The left graph shows the original infrastructure.
          The right graph shows the changed version. SABLE traces how the role connects to
          the bucket through the policy nodes.
        </div>
      )}
    </div>
  );
};
