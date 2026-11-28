import { spawn } from 'node:child_process';
import path from 'node:path';

export type FaceMatchResult =
  | {
      status: 'compared';
      cosineSimilarity: number;
      method: 'opencv_sface';
    }
  | {
      status: 'inconclusive';
      message: string;
    };

export function compareEnrolledFace(
  enrolled: string,
  camera: string
): Promise<FaceMatchResult> {

  return new Promise((resolve) => {

    const fail = (message: string) => {
      resolve({ status: 'inconclusive', message });
    };

    if (
      !enrolled ||
      !camera ||
      enrolled.length > 4_200_000 ||
      camera.length > 4_200_000
    ) {
      fail('Invalid image input.');
      return;
    }

    const python =
      process.env.FACE_PYTHON_PATH ||
      path.resolve('.venv-face/bin/python');

    const script = path.resolve(
      'python-ai/face_match_cli.py'
    );

    const child = spawn(python, [script], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let settled = false;

    const finish = (result: FaceMatchResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish({
        status: 'inconclusive',
        message: 'Face comparison timed out.'
      });
    }, 30000);

    child.stdout.on('data', chunk => {
      output += chunk.toString();

      if (output.length > 16000) {
        child.kill('SIGKILL');
        finish({
          status: 'inconclusive',
          message: 'Invalid engine response.'
        });
      }
    });

    child.stderr.resume();

    child.on('error', () => {
      finish({
        status: 'inconclusive',
        message: 'Face comparison engine unavailable.'
      });
    });

    child.stdin.on('error', () => {
      child.kill();
      finish({
        status: 'inconclusive',
        message: 'Engine input failed.'
      });
    });

    child.on('close', code => {

      try {
        if (code !== 0) throw new Error();

        const result = JSON.parse(output);
        const score = result.cosineSimilarity;

        if (
          result.status === 'compared' &&
          result.method === 'opencv_sface' &&
          typeof score === 'number' &&
          Number.isFinite(score) &&
          score >= -1 &&
          score <= 1
        ) {
          finish({
            status: 'compared',
            cosineSimilarity: score,
            method: 'opencv_sface'
          });
        } else {
          throw new Error();
        }

      } catch {
        finish({
          status: 'inconclusive',
          message: 'Facial comparison unsuccessful.'
        });
      }
    });

    child.stdin.end(JSON.stringify({
      enrolled,
      camera
    }));
  });
}
