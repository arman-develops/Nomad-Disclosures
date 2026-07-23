import fs from "fs";
import path from "path";

const CASE_STUDIES = path.join(process.cwd(), "Case-Studies");

const folders = fs
  .readdirSync(CASE_STUDIES)
  .filter(name =>
    fs.statSync(path.join(CASE_STUDIES, name)).isDirectory()
  )
  .sort((a, b) => {
    // DD-MM-YYYY
    const [d1, m1, y1] = a.split("-").map(Number);
    const [d2, m2, y2] = b.split("-").map(Number);

    return (
      new Date(y2, m2 - 1, d2).getTime() -
      new Date(y1, m1 - 1, d1).getTime()
    );
  });

const output = path.join(CASE_STUDIES, ".index.json");

fs.writeFileSync(
  output,
  JSON.stringify(folders, null, 2) + "\n"
);

console.log(`Generated ${output}`);
