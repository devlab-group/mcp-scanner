import pg from "pg";

const pool = new pg.Pool();

export async function query(sql) {
  const res = await pool.query(sql);
  return res.rows;
}
