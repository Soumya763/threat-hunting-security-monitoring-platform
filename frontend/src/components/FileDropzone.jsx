import { useRef, useState } from "react";
import { formatBytes } from "../utils/format";

// Drag-and-drop or click-to-choose. Validation here is only a convenience;
// the backend enforces the extension, size and content checks.
export default function FileDropzone({ file, onFile, disabled, allowedExtensions, maxBytes }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [problem, setProblem] = useState(null);

  function accept(candidate) {
    if (!candidate) return;
    const ext = candidate.name.includes(".") ? candidate.name.split(".").pop().toLowerCase() : "";
    if (allowedExtensions && !allowedExtensions.includes(ext)) {
      setProblem(`'.${ext || "none"}' files are not supported.`);
      return;
    }
    if (maxBytes && candidate.size > maxBytes) {
      setProblem(`The file is ${formatBytes(candidate.size)}; the limit is ${formatBytes(maxBytes)}.`);
      return;
    }
    if (candidate.size === 0) {
      setProblem("The file is empty.");
      return;
    }
    setProblem(null);
    onFile(candidate);
  }

  return (
    <div>
      <div
        className={`dropzone${dragging ? " dropzone--active" : ""}${disabled ? " dropzone--disabled" : ""}`}
        onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (!disabled) accept(e.dataTransfer.files?.[0]);
        }}
      >
        <p className="dropzone__title">{file ? file.name : "Drop a file here"}</p>
        <p className="ta-muted">
          {file ? `${formatBytes(file.size)} selected` : "or choose a file from your computer"}
        </p>
        <button type="button" className="btn" disabled={disabled}
          onClick={() => inputRef.current?.click()}>
          {file ? "Choose another file" : "Choose file"}
        </button>
        <input
          ref={inputRef}
          type="file"
          className="visually-hidden"
          aria-label="Choose a file to analyse"
          disabled={disabled}
          onChange={(e) => accept(e.target.files?.[0])}
        />
      </div>
      {problem ? <p className="ta-error" role="alert">{problem}</p> : null}
    </div>
  );
}
