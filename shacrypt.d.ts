declare module "shacrypt" {
  export function sha256crypt(
    password: string,
    salt?: string,
    rounds?: number
  ): string;

  export function sha256cryptAsync(
    password: string,
    salt: string | undefined,
    rounds: number | undefined,
    cb: (err: Error | undefined, res: string) => void
  ): void;

  export function sha256cryptAsync(
    password: string,
    salt?: string,
    rounds?: number
  ): Promise<string>;

  export function sha512crypt(
    password: string,
    salt?: string,
    rounds?: number
  ): string;

  export function sha512cryptAsync(
    password: string,
    salt: string | undefined,
    rounds: number | undefined,
    cb: (err: Error | undefined, res: string) => void
  ): void;

  export function sha512cryptAsync(
    password: string,
    salt?: string,
    rounds?: number
  ): Promise<string>;

  export function verify(
    password: string,
    storedHash: string
  ): Promise<boolean>;
}
