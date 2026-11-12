export const ACTION = 'github.issue.create';
// Exclude path segments that URL normalization could interpret as traversal.
export const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
