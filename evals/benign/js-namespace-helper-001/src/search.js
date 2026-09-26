const NOTES = ["buy milk", "renew the domain"];

export function query(term) {
  return NOTES.filter((note) => note.includes(term));
}
