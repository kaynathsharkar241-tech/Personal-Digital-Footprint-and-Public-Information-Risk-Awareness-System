import React, { useEffect, useState } from 'react';
import { BookOpen, CheckCircle2, ExternalLink, Search } from 'lucide-react';
import { apiRequest } from '../lib/api.ts';
import type { ResponseGuide } from '../lib/types.ts';
import { AWARENESS_GUIDES } from './awarenessGuides.ts';

interface Question {
  id: number;
  weight: number;
  text: string;
  options: Array<{ value: number; label: string }>;
}

interface SearchLinkItem {
  term: string;
  googleUrl: string;
  duckDuckGoUrl: string;
}

interface QuestionnaireViewProps {
  onScoreSaved: () => void;
}

export const QuestionnaireView: React.FC<QuestionnaireViewProps> = ({ onScoreSaved }) => {
  const [questions, setQuestions] = useState<Question[]>([]);
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [score, setScore] = useState<number | null>(null);
  const [links, setLinks] = useState<SearchLinkItem[]>([]);
  const [guides, setGuides] = useState<Record<string, ResponseGuide>>({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      apiRequest<{ questions: Question[]; answers: Record<number, number>; score: number | null }>(
        '/api/questionnaire'
      ),
      apiRequest<{ links: SearchLinkItem[]; guides: Record<string, ResponseGuide> }>(
        '/api/guided-search'
      ),
    ])
      .then(([qRes, gRes]) => {
        setQuestions(qRes.questions);
        setAnswers(qRes.answers);
        setScore(qRes.score);
        setLinks(gRes.links);
        setGuides(gRes.guides);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load assessment tools.');
      });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMsg(null);
    for (const q of questions) {
      if (answers[q.id] === undefined) {
        setError(`Please select an option for Question ${q.id}.`);
        return;
      }
    }
    setSaving(true);
    try {
      const res = await apiRequest<{ score: number }>('/api/questionnaire', {
        method: 'POST',
        body: JSON.stringify({ answers }),
      });
      setScore(res.score);
      setMsg(`Exposure score updated: ${res.score}/100.`);
      onScoreSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save questionnaire.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8">
      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      )}
      {msg && (
        <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-200 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{msg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Weighted Exposure Questionnaire */}
        <section className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Weighted Digital Exposure Questionnaire
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Answers compute your 0–100 personal exposure index alongside discovered findings.
              </p>
            </div>
            <div className="text-right">
              <div className="text-[11px] uppercase tracking-wider text-slate-400">Current Score</div>
              <div className="font-mono text-2xl font-semibold tabular-nums text-[#15395A] dark:text-sky-400">
                {score === null ? '—' : `${score}/100`}
              </div>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="mt-5 space-y-5">
            {questions.map((q) => (
              <fieldset
                key={q.id}
                className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 space-y-3"
              >
                <legend className="text-xs font-semibold text-slate-800 dark:text-slate-200 px-1">
                  {questions.findIndex((item) => item.id === q.id) + 1}. {q.text} (Weight: {q.weight})
                </legend>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                  {q.options.map((opt) => (
                    <label
                      key={opt.value}
                      className={`flex items-center gap-2 rounded-md border px-3 py-2 cursor-pointer transition-colors ${
                        answers[q.id] === opt.value
                          ? 'border-[#15395A] bg-[#15395A]/5 dark:border-sky-500 dark:bg-sky-500/10 font-medium'
                          : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'
                      }`}
                    >
                      <input
                        type="radio"
                        name={`q-${q.id}`}
                        checked={answers[q.id] === opt.value}
                        onChange={() => setAnswers((a) => ({ ...a, [q.id]: opt.value }))}
                        className="accent-[#15395A]"
                      />
                      <span>{opt.label} ({opt.value})</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}

            <button
              type="submit"
              disabled={saving}
              className="px-5 py-2.5 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white text-xs font-medium disabled:opacity-50 cursor-pointer"
            >
              {saving ? 'Calculating Score...' : 'Save Answers & Recalculate Score'}
            </button>
          </form>
        </section>

        {/* Guided Manual Self-Check Links */}
        <section className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Guided Manual Self-Check Links
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Exact-phrase queries built from your saved Monitoring identifiers.
              </p>
            </div>
            <Search className="w-4 h-4 text-slate-400" />
          </div>

          {links.length === 0 ? (
            <p className="text-xs text-slate-500">
              Add your full name, handle, or extra terms under Monitoring &amp; Scans to generate exact-match self-check queries.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {links.map((item) => (
                <div key={item.term} className="py-3 flex items-center justify-between gap-3">
                  <span className="font-mono text-xs text-slate-800 dark:text-slate-200 truncate">
                    &ldquo;{item.term}&rdquo;
                  </span>
                  <div className="flex items-center gap-2 shrink-0 text-xs">
                    <a
                      href={item.googleUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 px-2.5 py-1 hover:bg-slate-50 dark:hover:bg-slate-800"
                    >
                      Google
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <a
                      href={item.duckDuckGoUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 px-2.5 py-1 hover:bg-slate-50 dark:hover:bg-slate-800"
                    >
                      DuckDuckGo
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Practical guides imported from the Digital Footprint Scanner project */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">Practical Digital Safety Guides</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Step-by-step guidance for common privacy and account-security situations.</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {AWARENESS_GUIDES.map((guide) => (
            <article key={guide.id} className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{guide.title}</h3>
                <span className={`text-[10px] uppercase font-semibold rounded-full px-2 py-1 ${guide.severity === 'high' ? 'bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300' : 'bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300'}`}>{guide.severity} risk</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400">{guide.what}</p>
              <h4 className="text-xs font-semibold">What to do now</h4>
              <ol className="list-decimal pl-4 space-y-1 text-xs text-slate-700 dark:text-slate-300">
                {guide.steps.map((step, index) => <li key={index}>{step}</li>)}
              </ol>
              <h4 className="text-xs font-semibold">Where to get help</h4>
              <ul className="space-y-1 text-xs">
                {guide.help.map((item, index) => (
                  <li key={index}>
                    {item.url ? <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-[#15395A] dark:text-sky-400 hover:underline">{item.label}</a> : <span>{item.label}</span>}
                  </li>
                ))}
              </ul>
              <h4 className="text-xs font-semibold">How to stay safe next time</h4>
              <ul className="list-disc pl-4 space-y-1 text-xs text-slate-700 dark:text-slate-300">
                {guide.prevent.map((step, index) => <li key={index}>{step}</li>)}
              </ul>
            </article>
          ))}
        </div>
      </section>

      {/* Category Response Playbooks */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
        <div className="flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-[#15395A] dark:text-sky-400" />
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Category Response Guides &amp; Removal Playbooks
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Object.entries(guides).map(([cat, guide]) => (
            <article
              key={cat}
              className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 flex flex-col justify-between space-y-3"
            >
              <div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{cat}</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 leading-relaxed">
                  {guide.summary}
                </p>
                <ol className="mt-3 list-decimal pl-4 space-y-1 text-xs text-slate-700 dark:text-slate-300">
                  {guide.steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ol>
              </div>
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
                <a
                  href={guide.resourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-medium text-[#15395A] dark:text-sky-400 hover:underline"
                >
                  {guide.resourceLabel}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
};
