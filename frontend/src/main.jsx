import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { ShieldCheck, ShieldAlert, Search, Github, Activity } from "lucide-react";
import "./style.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyze(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Analysis failed.");
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const dangerous = result?.label === "phishing";

  return (
    <div className="page">
      <nav>
        <div className="brand"><ShieldCheck size={25}/> PhishGuard AI</div>
        <a href="https://github.com/" target="_blank" rel="noreferrer">
          <Github size={19}/> GitHub
        </a>
      </nav>

      <main>
        <section className="hero">
          <div className="eyebrow"><Activity size={16}/> MACHINE LEARNING SECURITY</div>
          <h1>Detect suspicious URLs before they become a problem.</h1>
          <p>
            A full-stack phishing URL detection system combining lexical URL analysis,
            character-level machine learning, and explainable risk indicators.
          </p>

          <form onSubmit={analyze} className="scanner">
            <Search size={21}/>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              required
            />
            <button disabled={loading}>
              {loading ? "Analyzing..." : "Scan URL"}
            </button>
          </form>
          {error && <div className="error">{error}</div>}
        </section>

        {result && (
          <section className={`result ${dangerous ? "danger" : "safe"}`}>
            <div className="resultTop">
              <div className="icon">
                {dangerous ? <ShieldAlert size={38}/> : <ShieldCheck size={38}/>}
              </div>
              <div>
                <span className="small">DETECTION RESULT</span>
                <h2>{dangerous ? "Potential phishing URL" : "Likely legitimate URL"}</h2>
                <p className="target">{result.url}</p>
              </div>
              <div className="score">
                <strong>{result.risk_score}%</strong>
                <span>risk score</span>
              </div>
            </div>

            <div className="meter">
              <div style={{ width: `${result.risk_score}%` }} />
            </div>

            <div className="grid">
              <div className="card">
                <span className="small">PHISHING PROBABILITY</span>
                <h3>{(result.phishing_probability * 100).toFixed(2)}%</h3>
              </div>
              <div className="card">
                <span className="small">INDICATORS FOUND</span>
                <h3>{result.indicators.length}</h3>
              </div>
              <div className="card">
                <span className="small">URL LENGTH</span>
                <h3>{result.features.url_length}</h3>
              </div>
            </div>

            <div className="indicators">
              <h3>Risk indicators</h3>
              {result.indicators.length ? (
                <ul>{result.indicators.map((x) => <li key={x}>{x}</li>)}</ul>
              ) : (
                <p>No obvious lexical phishing indicators were detected.</p>
              )}
            </div>
          </section>
        )}

        <section className="about">
          <div>
            <span className="small">HOW IT WORKS</span>
            <h2>Two layers of URL intelligence</h2>
          </div>
          <div className="grid">
            <div className="card">
              <h3>Lexical analysis</h3>
              <p>Examines URL length, IP usage, subdomains, special characters, suspicious words, entropy and more.</p>
            </div>
            <div className="card">
              <h3>ML classification</h3>
              <p>Character n-gram TF-IDF features are combined with engineered URL features and classified by a Random Forest.</p>
            </div>
            <div className="card">
              <h3>Explainable output</h3>
              <p>Returns a probability, risk score and human-readable indicators instead of only a binary prediction.</p>
            </div>
          </div>
        </section>
      </main>

      <footer>
        Built as a cybersecurity + machine learning portfolio project.
      </footer>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
