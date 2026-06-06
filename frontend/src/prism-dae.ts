import { languages } from "solid-prism-editor/prism";

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
