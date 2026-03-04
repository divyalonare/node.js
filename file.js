const fs = require("fs");

fs.writeFile('./test.txt',"test data asyn" , (err) => {});

const result = fs.readFileSync('./details.txt', 'utf-8');
console.log(result);

fs.appendFileSync('./test.txt', "\nappended data sync ");
const logEntry = `Log entry at: ${new Date().toLocaleString()}\n`;
fs.appendFileSync("./test.txt", logEntry);

console.log("Date has been logged!");
fs.appendFileSync("./test.txt", `${Date.now()} hello\n`);
fs.cpSync('./test.txt', './test_copy.txt');

fs.unlinkSync('./test_copy.txt');
console.log(fs.statSync('./test.txt'));
fs.mkdirSync('.myDir/ab/cd', { recursive: true });