import { X } from 'lucide-react';

export default function EventInspectorModal({ entry, onClose }) {
  if (!entry) return null;
  return (
    <div className="inspector-overlay" onClick={onClose}>
      <div className="inspector-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">Log entry</div>
          <button onClick={onClose} className="filter-btn" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <pre className="json-codeblock">{JSON.stringify(entry, null, 2)}</pre>
      </div>
    </div>
  );
}
