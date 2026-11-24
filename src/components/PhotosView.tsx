import React, { useEffect, useState } from 'react';
import { ImagePlus, ShieldCheck, Trash2, Upload } from 'lucide-react';
import { apiRequest, fileToDataUrl } from '../lib/api.ts';
import type { MonitoringPhoto, UserState } from '../lib/types.ts';
import { ProtectedImage } from './ProtectedImage.tsx';

interface PhotosViewProps {
  user: UserState;
  onUserUpdated: (user: UserState) => void;
  onRefreshDashboard: () => void;
}

export const PhotosView: React.FC<PhotosViewProps> = ({
  user,
  onUserUpdated,
  onRefreshDashboard,
}) => {
  const [photos, setPhotos] = useState<MonitoringPhoto[]>([]);
  const [label, setLabel] = useState('');
  const [previewDataUrl, setPreviewDataUrl] = useState('');
  const [uploading, setUploading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadPhotos = async () => {
    try {
      const res = await apiRequest<{ photos: MonitoringPhoto[] }>('/api/photos');
      setPhotos(res.photos);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load monitoring photos.');
    }
  };

  useEffect(() => {
    loadPhotos();
  }, []);

  const handleToggleAiConsent = async (consent: boolean) => {
    setError(null);
    setMsg(null);
    try {
      const res = await apiRequest<{ ok: boolean; user: UserState }>('/api/identity/ai-consent', {
        method: 'PUT',
        body: JSON.stringify({ consent }),
      });
      onUserUpdated(res.user);
      setMsg(
        consent
          ? 'Opted in to third-party Google Gemini API 1:1 visual screening.'
          : 'Disabled third-party Google Gemini biometric screening; uploaded photos stay encrypted locally.'
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update AI screening preference.');
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const dataUrl = await fileToDataUrl(file);
      setPreviewDataUrl(dataUrl);
      if (!label) setLabel(file.name.replace(/\.[^.]+$/, ''));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not read image.');
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!previewDataUrl) {
      setError('Select an image file first.');
      return;
    }
    setError(null);
    setMsg(null);
    setUploading(true);
    try {
      const res = await apiRequest<{
        id: number;
        matchResult: string;
        matchReason: string;
        matchConfidence: number | null;
      }>('/api/photos', {
        method: 'POST',
        body: JSON.stringify({
          label: label.trim() || 'Monitoring Photo',
          imageDataUrl: previewDataUrl,
        }),
      });
      setPreviewDataUrl('');
      setLabel('');
      setMsg(
        `Encrypted photo uploaded. 1:1 screening status: ${res.matchResult} — ${res.matchReason}`
      );
      await loadPhotos();
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed.');
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: number) => {
    setError(null);
    try {
      await apiRequest(`/api/photos/${id}`, { method: 'DELETE' });
      setPhotos((prev) => prev.filter((p) => p.id !== id));
      onRefreshDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete photo.');
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-4 py-3 text-sm text-red-800 dark:text-red-200">
          {error}
        </div>
      )}
      {msg && (
        <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-200">
          {msg}
        </div>
      )}

      {/* Upload & Optional 1:1 Screening Form */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Encrypted Monitoring Photo Vault (1:1 Face Screening)
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
            Upload photos of yourself (or suspected impersonation candidates) up to 10 MB, stored encrypted locally with AES-256-GCM. When opted in below, Google Gemini runs advisory 1:1 visual similarity and editing/anomaly observations for human review. Dedicated DeepFace/ArcFace neural embeddings, forensic deepfake detectors, and automated open-web reverse-image uploads are not integrated here so private photographs never leave your encrypted vault unconsented.
          </p>
        </div>

        <label className="flex items-start gap-2.5 text-xs text-slate-600 dark:text-slate-300 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 cursor-pointer">
          <input
            type="checkbox"
            checked={user.aiBiometricConsent}
            onChange={(e) => handleToggleAiConsent(e.target.checked)}
            className="mt-0.5 rounded border-slate-300"
          />
          <span>
            <strong>Optional Third-Party Processing Disclosure:</strong> Enable sending uploaded photos and your enrollment selfie to the external Google Gemini API for 1:1 visual similarity screening. Leave unchecked to keep photos exclusively on this server for manual reviewer audit.
          </span>
        </label>

        <form onSubmit={handleUpload} className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-5">
            <label className="block text-xs font-medium mb-1">Photo Label</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. LinkedIn Avatar or Public Event Photo"
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
            />
          </div>

          <div className="md:col-span-4">
            <label className="block text-xs font-medium mb-1">Select Image (JPEG / PNG / WebP)</label>
            <label className="flex items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer">
              <Upload className="w-3.5 h-3.5" />
              <span>{previewDataUrl ? 'Change Selected Photo' : 'Choose Image File'}</span>
              <input
                type="file"
                accept="image/jpeg,image/png,image/webp"
                onChange={handleFileChange}
                className="sr-only"
              />
            </label>
          </div>

          <div className="md:col-span-3">
            <button
              type="submit"
              disabled={uploading || !previewDataUrl}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-[#15395A] hover:bg-[#102d47] text-white py-2.5 px-4 text-xs font-medium disabled:opacity-50 cursor-pointer"
            >
              <ImagePlus className="w-3.5 h-3.5" />
              {uploading
                ? 'Encrypting...'
                : user.aiBiometricConsent
                ? 'Encrypt & Screen Photo'
                : 'Encrypt & Queue Photo'}
            </button>
          </div>
        </form>

        {previewDataUrl && (
          <div className="flex items-center gap-3 pt-2">
            <img
              src={previewDataUrl}
              alt="Upload preview"
              className="w-16 h-16 rounded-lg object-cover border border-slate-200 dark:border-slate-700"
            />
            <span className="text-xs text-slate-600 dark:text-slate-400">
              {user.aiBiometricConsent
                ? 'Ready to encrypt and compare against your enrolled selfie.'
                : 'Ready to encrypt locally and queue for manual reviewer inspection.'}
            </span>
          </div>
        )}
      </section>

      {/* Vault Grid */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Stored Monitoring Photos ({photos.length} / 20)
          </h2>
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            AES-256-GCM Encrypted
          </span>
        </div>

        {photos.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 dark:border-slate-800 p-8 text-center text-xs text-slate-500">
            No monitoring photos stored yet.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {photos.map((p) => (
              <article
                key={p.id}
                className="rounded-lg border border-slate-200 dark:border-slate-800 overflow-hidden flex flex-col"
              >
                <ProtectedImage
                  src={`/api/photos/${p.id}/image`}
                  alt={p.label}
                  className="w-full h-44 object-cover bg-slate-100 dark:bg-slate-950"
                />
                <div className="p-4 flex-1 flex flex-col justify-between space-y-3 text-xs">
                  <div className="space-y-1.5">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
                        {p.label}
                      </h3>
                      <button
                        type="button"
                        onClick={() => handleDelete(p.id)}
                        title="Delete photo"
                        className="text-slate-400 hover:text-red-600 cursor-pointer shrink-0"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 text-slate-600 dark:text-slate-400">
                      <span
                        className={`font-semibold ${
                          p.match_result === 'match'
                            ? 'text-emerald-700 dark:text-emerald-400'
                            : p.match_result === 'no_match'
                            ? 'text-red-600 dark:text-red-400'
                            : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        1:1 Screening: {p.match_result}
                      </span>
                      {p.match_confidence !== null && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono tabular-nums">
                            {Math.round(p.match_confidence * 100)}%
                          </span>
                        </>
                      )}
                      <span aria-hidden="true">·</span>
                      <span>Review: {p.status.replace('_', ' ')}</span>
                    </div>

                    {p.match_reason && (
                      <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                        {p.match_reason}
                      </p>
                    )}
                    {p.reviewer_note && (
                      <p className="text-slate-500">Reviewer note: {p.reviewer_note}</p>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-slate-400 tabular-nums pt-2 border-t border-slate-100 dark:border-slate-800">
                    Uploaded {p.created_at.slice(0, 16).replace('T', ' ')}
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
