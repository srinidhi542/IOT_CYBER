import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("ErrorBoundary caught an unhandled error:", error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="dark-panel p-8 border border-rose-800/80 bg-rose-950/20 max-w-xl mx-auto my-8 space-y-4 text-center">
          <div className="w-12 h-12 rounded-xl bg-rose-950/80 border border-rose-700/60 flex items-center justify-center text-rose-400 mx-auto">
            <AlertTriangle size={24} />
          </div>
          <div>
            <h4 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              {this.props.fallbackTitle || "Render Exception Intercepted"}
            </h4>
            <p className="text-xs font-mono text-rose-300 mt-1 max-w-md mx-auto">
              {this.state.error?.message || "An unexpected error occurred while rendering this section."}
            </p>
          </div>
          <button
            onClick={this.handleReset}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-900/60 hover:bg-rose-800 border border-rose-600/60 text-white font-mono text-xs font-bold uppercase transition-all shadow"
          >
            <RotateCcw size={13} />
            <span>Reload View</span>
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
