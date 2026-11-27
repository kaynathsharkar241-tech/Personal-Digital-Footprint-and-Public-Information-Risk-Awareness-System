import { spawn } from 'node:child_process';
import path from 'node:path';

export interface FaceInspection {
  status: 'passed' | 'failed' | 'inconclusive';
  faceCount?: number;
  brightness?: number;
  sharpness?: number;
  reason: string;
}

export function inspectFace(
  image: Buffer
): Promise<FaceInspection> {
  return new Promise((resolve) => {
    if (image.length > 3 * 1024 * 1024) {
      resolve({
        status: 'failed',
        reason: 'Image exceeds 3 MB'
      });
      return;
    }

    const python = process.env.FACE_PYTHON_PATH ||
      path.resolve('.venv-face/bin/python');

    const script = path.resolve(
      'python-ai/face_engine.py'
    );

    const child = spawn(python, [script], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({
        status: 'inconclusive',
        reason: 'Image processing timed out'
      });
    }, 30000);

    child.stdout.on('data', (data) => {
      output += data.toString();

      if (output.length > 65536) {
        child.kill('SIGKILL');
      }
    });

    child.stderr.on('data', () => {});

    child.on('error', () => {
      clearTimeout(timer);
      resolve({
        status: 'inconclusive',
        reason: 'Image processing engine unavailable'
      });
    });

    child.stdin.on('error', () => {});

    child.on('close', (code) => {
      clearTimeout(timer);

      try {
        if (code !== 0) throw new Error();

        const result = JSON.parse(output);

        if (!['passed', 'failed', 'inconclusive']
          .includes(result.status)) {
          throw new Error();
        }

        resolve(result);
      } catch {
        resolve({
          status: 'inconclusive',
          reason: 'Invalid image processing response'
        });
      }
    });

    child.stdin.end(JSON.stringify({
      mode: 'inspect',
      image: image.toString('base64')
    }));
  });
}

export interface MovementAssessment {
  status: 'passed' | 'failed' | 'inconclusive';
  movement?: number;
  returnError?: number;
  method?: string;
  reason: string;
}

export function assessMovement(
  frames: Buffer[]
): Promise<MovementAssessment> {
  return new Promise((resolve) => {
    const failure = (reason: string): MovementAssessment => ({
      status: 'inconclusive',
      reason
    });

    if (
      frames.length !== 3 ||
      frames.some(f => f.length > 3 * 1024 * 1024)
    ) {
      resolve(failure('Invalid camera frames'));
      return;
    }

    const python = process.env.FACE_PYTHON_PATH ||
      path.resolve('.venv-face/bin/python');

    const child = spawn(
      python,
      [path.resolve('python-ai/face_engine.py')],
      { stdio: ['pipe', 'pipe', 'pipe'] }
    );

    let output = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve(failure('Movement assessment timed out'));
    }, 30000);

    child.stdout.on('data', data => {
      output += data.toString();

      if (output.length > 65536) {
        child.kill('SIGKILL');
      }
    });

    child.stderr.on('data', () => {});

    child.stdin.on('error', () => {});

    child.on('error', () => {
      clearTimeout(timer);
      resolve(failure('Movement engine unavailable'));
    });

    child.on('close', code => {
      clearTimeout(timer);

      try {
        if (code !== 0) throw new Error();

        const result = JSON.parse(output);

        if (
          !['passed', 'failed', 'inconclusive']
            .includes(result.status)
        ) {
          throw new Error();
        }

        resolve(result);
      } catch {
        resolve(failure('Invalid movement engine response'));
      }
    });

    child.stdin.end(JSON.stringify({
      mode: 'liveness',
      frames: frames.map(f => f.toString('base64'))
    }));
  });
}
