// Lets a question an OMP agent asks be answered from the phone as well as at
// the keyboard. OMP loads this file as an extension:
// `omp --trusted-extension <this file>`.
//
// It stands in for the built-in `ask` tool and runs the built-in underneath
// (OMP's documented `ctx.invokeTool`), so the form opens in the terminal
// exactly as it did. While the form is open it also waits for an answer the
// Pairling daemon may write beside a marker this file leaves. Whichever comes
// first is the answer and the other is dropped. When anything Pairling needs
// is missing, the built-in is left alone.
//
// Checked against OMP 18.20.2.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, watch, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// OMP exits when a trusted extension fails to load, and a person's own omp
// command names this file. So nothing here may fail while it loads: whatever
// is missing, OMP starts and the built-in `ask` is left alone.
let omp;
try {
	// OMP gives an extension its own modules under this name.
	omp = await import("@oh-my-pi/pi-coding-agent");
} catch {
	// builtInAsk then finds nothing to take.
}

const COMPANION = join(homedir(), ".claude", "companion");
// An open form is `<session id>.<call key>.pending`, holding this process's
// id. An answer for it is `<session id>.<call key>.answer.json`. Each is
// renamed into place whole, so the other side never reads half of one. The
// call key is a digest of the call's id, because that id is the model
// provider's and may hold any character.
const ASKS = join(COMPANION, "omp-asks");

function drop(file) {
	try {
		rmSync(file, { force: true });
	} catch {
		// Left for the daemon, which ignores a marker whose process has gone.
	}
}

// What the stand-in takes from the built-in so that nothing else about a
// question changes: how it is checked, that it needs no approval and runs
// alone, and how the terminal draws it. Undefined when this OMP does not
// offer all of it.
function builtInAsk() {
	try {
		const tool = new omp.AskTool({});
		const drawn = omp.askToolRenderer;
		if (tool.name !== "ask" || !tool.parameters) return;
		if (typeof drawn?.renderCall !== "function" || typeof drawn?.renderResult !== "function") return;
		return {
			name: tool.name,
			label: tool.label,
			summary: tool.summary,
			parameters: tool.parameters,
			strict: tool.strict,
			approval: tool.approval,
			concurrency: tool.concurrency,
			loadMode: tool.loadMode,
			...drawn,
		};
	} catch {
		return;
	}
}

function answerFromPairling(answerFile, pending, signal) {
	return new Promise(resolve => {
		let watcher;
		const read = () => {
			let answer;
			try {
				answer = JSON.parse(readFileSync(answerFile, "utf8"));
			} catch {
				// Not there yet: the daemon renames a whole file into place.
				return;
			}
			if (answer && answer.data && typeof answer.data === "object" && Array.isArray(answer.answers)) {
				watcher.close();
				resolve(answer);
			}
		};
		// Without a watch the form takes an answer at the keyboard only, so
		// the marker that offers the other way goes.
		try {
			watcher = watch(ASKS, read);
		} catch {
			drop(pending);
			return;
		}
		watcher.on("error", () => {
			watcher.close();
			drop(pending);
		});
		signal.addEventListener("abort", () => watcher.close(), { once: true });
		read();
	});
}

export default function pairlingAsk(pi) {
	let standsIn = false;
	const standIn = () => {
		if (standsIn) return;
		// No built-in in this session, no stand-in: a session that was not
		// given `ask` does not gain one here.
		const listed = pi.getAllTools().find(tool => tool.name === "ask");
		if (!listed || !String(listed.sourceInfo?.path ?? "").startsWith("<builtin")) return;
		const builtIn = builtInAsk();
		if (!builtIn) return;
		standsIn = true;
		pi.registerTool({
			...builtIn,
			// The model is told about `ask` in the built-in's own words.
			description: listed.description,
			async execute(callId, params, signal, _onUpdate, ctx) {
				const sessionId = String(ctx.sessionManager?.getSessionId?.() ?? "");
				if (!existsSync(COMPANION) || !/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) {
					return ctx.invokeTool(params, { signal });
				}
				const callKey = createHash("sha256").update(String(callId)).digest("hex").slice(0, 32);
				const pending = join(ASKS, `${sessionId}.${callKey}.pending`);
				const answerFile = join(ASKS, `${sessionId}.${callKey}.answer.json`);
				try {
					mkdirSync(ASKS, { recursive: true, mode: 0o700 });
					writeFileSync(`${pending}.tmp`, String(process.pid), { mode: 0o600 });
					renameSync(`${pending}.tmp`, pending);
				} catch {
					drop(`${pending}.tmp`);
					return ctx.invokeTool(params, { signal });
				}
				const open = new AbortController();
				const stop = () => open.abort();
				signal?.addEventListener("abort", stop, { once: true });
				if (signal?.aborted) open.abort();
				try {
					const atTheKeyboard = ctx.invokeTool(params, { signal: open.signal }).then(
						result => ({ result }),
						error => ({ error }),
					);
					const fromPairling = answerFromPairling(answerFile, pending, open.signal).then(answer => ({ answer }));
					const first = await Promise.race([atTheKeyboard, fromPairling]);
					if (!first.answer) {
						if (first.error) throw first.error;
						return first.result;
					}
					// Closes the form in the terminal. Its "cancelled" error is expected.
					open.abort();
					await atTheKeyboard;
					return {
						content: [{ type: "text", text: `User answers:\n${JSON.stringify(first.answer.data, null, 2)}` }],
						details: { answers: first.answer.answers },
					};
				} finally {
					open.abort();
					signal?.removeEventListener("abort", stop);
					drop(pending);
					drop(answerFile);
				}
			},
		});
	};
	try {
		pi.on("session_start", () => {
			try {
				standIn();
			} catch {
				// The built-in is left alone.
			}
		});
	} catch {
		// An OMP that takes no such handler: the built-in is left alone.
	}
}
