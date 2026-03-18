import { useState, useCallback, useRef, useEffect } from "react";

interface ToastItem {
  id: number;
  message: string;
}

let nextId = 0;

export function useToast() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const showToast = useCallback((message: string, duration = 3000) => {
    const id = nextId++;
    setToasts(prev => [...prev, { id, message }]);
    const timer = setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
      timersRef.current.delete(id);
    }, duration);
    timersRef.current.set(id, timer);
  }, []);

  useEffect(() => {
    return () => {
      timersRef.current.forEach(t => clearTimeout(t));
    };
  }, []);

  return { toasts, showToast };
}

export default function ToastContainer({ toasts }: { toasts: ToastItem[] }) {
  if (toasts.length === 0) return null;

  return (
    <div style={{
      position: "fixed",
      bottom: 24,
      right: 24,
      zIndex: 99999,
      display: "flex",
      flexDirection: "column",
      gap: 8,
      pointerEvents: "none",
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          background: "var(--bg-dialog)",
          color: "var(--text-primary)",
          padding: "10px 20px",
          borderRadius: 6,
          fontSize: 13,
          boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
          animation: "toast-fade-in 0.2s ease",
        }}>
          {t.message}
        </div>
      ))}
      <style>{`
        @keyframes toast-fade-in {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
