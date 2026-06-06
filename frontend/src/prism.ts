import { languages } from "solid-prism-editor/prism";

// JSON grammar (inline to prevent tree-shaking)
languages.json ??= {
  property: /"(?:\\.|[^\\\n"])*"(?=\s*:)/g,
  string: /"(?:\\.|[^\\\n"])*"/g,
  comment: /\/\/.*|\/\*[^]*?(?:\*\/|$)/g,
  number: /-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/i,
  operator: /:/,
  punctuation: /[[\]{},]/,
  boolean: /\b(?:false|true)\b/,
  null: {
    pattern: /\bnull\b/,
    alias: "keyword",
  },
};

// dae grammar
const daeId = /[a-zA-Z_][a-zA-Z0-9_\/\\^*.+\-@$!#%]*/;

languages.dae = {
  comment: [{ pattern: /#.*/g }, { pattern: /\/\*[\s\S]*?(?:\*\/|$)/g }],
  string: [{ pattern: /"(?:[^"\\]|\\.)*"/g }, { pattern: /'(?:[^'\\]|\\.)*'/g }],
  keyword: {
    pattern: /\b(?:block|direct|must_direct|reject)\b/g,
  },
  operator: {
    pattern: /(?:&&|->|!)/g,
  },
  function: {
    pattern: new RegExp(daeId.source + "(?=\\s*\\()", "g"),
  },
  "class-name": {
    pattern: new RegExp(daeId.source + "(?=\\s*\\{)", "g"),
  },
  "attr-name": {
    pattern: new RegExp(daeId.source + "(?=\\s*: )", "g"),
  },
};
