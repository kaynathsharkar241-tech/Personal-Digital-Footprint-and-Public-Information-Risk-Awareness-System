import React, { useEffect, useState } from 'react';
import { ImageOff } from 'lucide-react';
import { fetchProtectedBlobUrl } from '../lib/api.ts';

interface ProtectedImageProps {
  src: string;
  alt: string;
  className?: string;
  useReviewerToken?: boolean;
  refreshKey?: number | string;
}

export const ProtectedImage: React.FC<ProtectedImageProps> = ({
  src,
  alt,
  className = '',
  useReviewerToken = false,
  refreshKey = 0,
}) => {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let active = true;
    let createdUrl: string | null = null;
    setError(false);
    setBlobUrl(null);

    fetchProtectedBlobUrl(src, useReviewerToken)
      .then((url) => {
        if (!active) {
          URL.revokeObjectURL(url);
          return;
        }
        createdUrl = url;
        setBlobUrl(url);
      })
      .catch(() => {
        if (active) setError(true);
      });

    return () => {
      active = false;
      if (createdUrl) URL.revokeObjectURL(createdUrl);
    };
  }, [src, useReviewerToken, refreshKey]);

  if (error) {
    return (
      <div
        className={`flex flex-col items-center justify-center bg-slate-100 dark:bg-slate-800/70 text-slate-500 dark:text-slate-400 p-4 text-center ${className}`}
      >
        <ImageOff className="w-5 h-5 mb-1.5 opacity-70" />
        <span className="text-xs">Protected preview unavailable</span>
      </div>
    );
  }

  if (!blobUrl) {
    return <div className={`animate-pulse bg-slate-200 dark:bg-slate-800 ${className}`} />;
  }

  return (
    <img
      src={blobUrl}
      alt={alt}
      referrerPolicy="no-referrer"
      className={className}
    />
  );
};
