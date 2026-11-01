// node-gyp-build ships no type declarations. Only used by checkJs; not published.
declare module 'node-gyp-build' {
  function load(dir: string): any;
  export = load;
}
