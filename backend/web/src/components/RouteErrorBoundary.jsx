import React from "react";
import { RefreshCw, ShieldAlert } from "lucide-react";

export default class RouteErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, retryKey: 0 };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidUpdate(previousProps) {
    if (previousProps.routeKey !== this.props.routeKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return <React.Fragment key={this.state.retryKey}>{this.props.children}</React.Fragment>;
    return <section className="panel route-error"><ShieldAlert size={28} /><div><h2>Module Load Failed</h2><p>{this.state.error.message || "Unknown error on page"}</p></div><button className="primary-button" onClick={() => this.setState((state) => ({ error: null, retryKey: state.retryKey + 1 }))}><RefreshCw size={15} />Reload Module</button></section>;
  }
}
