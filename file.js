const fs = require("fs");

fs.writeFile('./test.txt',"test data asyn" , (err) => {});

const result = fs.readFileSync('./details.txt', 'utf-8');
console.log(result);

fs.appendFileSync('./test.txt', "\nappended data sync ");
const logEntry = `Log entry at: ${new Date().toLocaleString()}\n`;
fs.appendFileSync("./test.txt", logEntry);

console.log("Date has been logged!");