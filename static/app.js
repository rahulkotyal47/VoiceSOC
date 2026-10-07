// Dashboard logic. Phase 1 only wires up the Run button and Enter key.
const input = document.getElementById("command");
const runBtn = document.getElementById("run");
const status = document.getElementById("status");

function runCommand() {
  const text = input.value.trim();
  if (!text) {
    status.textContent = "Type or speak a command first.";
    return;
  }
  // The /api/command route arrives in Phase 5.
  status.textContent = "Command received: " + text;
}

runBtn.addEventListener("click", runCommand);
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCommand();
});
