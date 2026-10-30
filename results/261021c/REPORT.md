# Proposed pipeline: agreement guard, Jev judge, blind checklist

Run `261021c`, scored 2026-10-30T02:12:49+00:00. Dataset commit `afe0ebd0adc237abb46255f9cd479b1d71819136`. Guard run `261021g`; hinted answers from `261020h` (first level: `261021b`).
Judge and checklist answerer `typesafe/jev-1.13` (yes when p >= 0.5); checklist writer `deepseek/deepseek-v4-pro`.

Stages: the agreement guard's priority tier; **+ Jev (hinted answers)** keeps a location when Jev,
reading both hinted LLMs' answers and the location's code, answers yes to: "True if the agents' final answers conclude that the method {method} is part of a path traversal vulnerability (it builds, passes or opens the attacker-controlled path).";
**+ checklist (Jev)** drops a location when Jev answers yes to every condition of a safe pattern in a
checklist DeepSeek wrote from CWE-22's description alone (one per sample). Sample k uses sample k of
every input.

Vulnerable revision: Detected, FDR, F1. Flagged = the patched fix method is still reported on the
fixed revision; Pair-correct = reported on the vulnerable revision and not the fixed one (projects
/6, per sample). Mean over samples, [min–max] when samples differ.

| Level | Stage | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | --- | ---: | ---: | --- | --- |
| HINTED | Agreement guard | 6/6, 6/6, 6/6 | 27.35% [19.44%–43.16%] | 0.7950 [0.6627–0.8611] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| HINTED | + Jev (hinted answers) | 6/6, 6/6, 6/6 | 5.56% [0.00%–16.67%] | 0.9630 [0.8889–1.0000] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| HINTED | **+ checklist (Jev)** | 6/6, 6/6, 6/6 | 5.56% [0.00%–16.67%] | 0.9630 [0.8889–1.0000] | 5/6, 5/6, 4/6 | 1/6, 1/6, 2/6 |
| H1 | Agreement guard | 5/6, 5/6, 5/6 | 40.90% [32.76%–57.18%] | 0.6074 [0.4667–0.6778] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| H1 | + Jev (hinted answers) | 5/6, 4/6, 5/6 | 25.19% [20.00%–27.78%] | 0.7222 [0.6667–0.7500] | 4/6, 4/6, 4/6 | 1/6, 0/6, 1/6 |
| H1 | **+ checklist (Jev)** | 5/6, 4/6, 5/6 | 25.19% [20.00%–27.78%] | 0.7222 [0.6667–0.7500] | 4/6, 3/6, 4/6 | 1/6, 1/6, 1/6 |
| H2A | Agreement guard | 5/6, 6/6, 6/6 | 32.78% [24.44%–49.44%] | 0.7145 [0.5663–0.7885] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H2A | + Jev (hinted answers) | 5/6, 6/6, 6/6 | 14.44% [10.00%–20.83%] | 0.8407 [0.7778–0.9000] | 6/6, 5/6, 4/6 | 0/6, 1/6, 2/6 |
| H2A | **+ checklist (Jev)** | 5/6, 6/6, 6/6 | 14.44% [10.00%–20.83%] | 0.8407 [0.7778–0.9000] | 5/6, 4/6, 3/6 | 1/6, 2/6, 3/6 |
| H2B | Agreement guard [Qwen selection] | 5/6, 6/6, 6/6 | 32.78% [24.44%–49.44%] | 0.7145 [0.5663–0.7885] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H2B | + Jev (hinted answers) [Qwen selection] | 5/6, 6/6, 6/6 | 4.17% [0.00%–12.50%] | 0.9111 [0.8333–1.0000] | 4/6, 5/6, 6/6 | 1/6, 1/6, 0/6 |
| H2B | **+ checklist (Jev) [Qwen selection]** | 5/6, 6/6, 6/6 | 4.17% [0.00%–12.50%] | 0.9111 [0.8333–1.0000] | 4/6, 4/6, 4/6 | 1/6, 2/6, 2/6 |
| H2B | Agreement guard [Deepseek selection] | 6/6, 6/6, 6/6 | 32.57% [24.43%–48.87%] | 0.7184 [0.5774–0.7889] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H2B | + Jev (hinted answers) [Deepseek selection] | 5/6, 6/6, 5/6 | 18.06% [16.67%–20.83%] | 0.8370 [0.8333–0.8444] | 4/6, 5/6, 6/6 | 1/6, 1/6, 0/6 |
| H2B | **+ checklist (Jev) [Deepseek selection]** | 5/6, 6/6, 5/6 | 18.06% [16.67%–20.83%] | 0.8370 [0.8333–0.8444] | 4/6, 5/6, 4/6 | 1/6, 1/6, 2/6 |
| E | Agreement guard [Qwen driver + selection] | 4/6, 5/6, 5/6 | 49.21% [40.71%–66.23%] | 0.5520 [0.3974–0.6293] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| E | + Jev (hinted answers) [Qwen driver + selection] | 4/6, 4/6, 3/6 | 13.89% [12.50%–16.67%] | 0.5556 [0.4444–0.6111] | 4/6, 4/6, 3/6 | 0/6, 0/6, 1/6 |
| E | **+ checklist (Jev) [Qwen driver + selection]** | 4/6, 4/6, 3/6 | 13.89% [12.50%–16.67%] | 0.5556 [0.4444–0.6111] | 4/6, 4/6, 2/6 | 0/6, 0/6, 2/6 |
| E | Agreement guard [Deepseek driver + selection] | 1/6, 1/6, 1/6 | 58.33% [50.00%–75.00%] | 0.1481 [0.1111–0.1667] | 1/6, 1/6, 1/6 | 0/6, 0/6, 0/6 |
| E | + Jev (hinted answers) [Deepseek driver + selection] | 1/6, 1/6, 1/6 | 0.00% | 0.1667 | 1/6, 1/6, 1/6 | 0/6, 0/6, 0/6 |
| E | **+ checklist (Jev) [Deepseek driver + selection]** | 1/6, 1/6, 1/6 | 0.00% | 0.1667 | 1/6, 1/6, 1/6 | 0/6, 0/6, 0/6 |

## Fix locations in the guard tier (Hinted level)

| Project | Revision | Fix location | Per sample |
| --- | --- | --- | --- |
| mpxj | fixed | `InputStreamHelper.processZipStream` | dropped by the checklist; dropped by the checklist; dropped by the checklist |
| mpxj | vulnerable | `InputStreamHelper.processZipStream` | kept; kept; kept |
| plexus-archiver | fixed | `AbstractUnArchiver.extractFile` | kept; kept; kept |
| plexus-archiver | vulnerable | `AbstractUnArchiver.extractFile` | kept; kept; kept |
| plexus-utils | fixed | `Expand.extractFile` | kept; kept; kept |
| plexus-utils | vulnerable | `Expand.extractFile` | kept; kept; kept |
| spark | fixed | `ClassPathResource.getInputStream` | kept; kept; kept |
| spark | vulnerable | `ClassPathResource.getInputStream` | kept; kept; kept |
| zip4j | fixed | `Unzip.initExtractFile` | kept; kept; dropped by the checklist |
| zip4j | vulnerable | `Unzip.initExtractFile` | kept; kept; kept |
| zt-zip | fixed | `Unpacker.process` | kept; kept; kept |
| zt-zip | vulnerable | `Unpacker.process` | kept; kept; kept |

## Blind checklists

Sample 1:

- **Canonical path containment using java.io.File**: Is the base directory path derived from a trusted source (e.g., a hardcoded string, a final field, or a constructor parameter) and not from user input? AND Does the method obtain the canonical form of the base directory by calling getCanonicalPath() (or getCanonicalFile().getPath()) on a File representing that directory? AND Does the method construct the target path by resolving the user input against the base directory, for example using new File(canonicalBaseDir, userInput)? AND Does the method obtain the canonical form of the target path by calling getCanonicalPath() (or getCanonicalFile().getPath()) on that File? AND Does the method check that the canonical target path starts with the canonical base directory path followed by File.separator (e.g., targetCanonical.startsWith(baseCanonical + File.separator))?
- **Path containment using java.nio.file.Path with toRealPath and normalize**: Is the base directory path trusted (e.g., from a constant, field, or configuration) and not derived from user input? AND Does the method obtain the real path of the base directory by calling Path.toRealPath() (with no arguments) on a Path object for that directory? AND Does the method ensure the user-supplied path is relative (e.g., by checking that it does not start with '/' and does not contain ':') before using it with resolve? AND Does the method resolve the user-relative path against the real base path using Path.resolve()? AND Does the method call Path.normalize() on the resolved path? AND Does the method verify that the normalized path starts with the real base path using Path.startsWith()?
- **Strict filename whitelist validation**: Is the base directory path trusted (constant, field not from input) and not constructed from user input? AND Does the method validate the user input against a regular expression that permits only safe filename characters (e.g., [a-zA-Z0-9._-]+) and explicitly forbids path separators, '..', and absolute path prefixes? AND Does the method use the validated input solely as the file name component, for instance by passing it to new File(trustedBaseDir, validatedName) or Paths.get(trustedBaseDir, validatedName)? AND Does the method avoid any other transformations of the user input that could introduce path separators after validation?
- **File path lookup via a predefined map**: Does the method use the user input solely as a key to retrieve a path from a predefined, static mapping (e.g., a Map<String, Path> initialized with constants, or a switch statement returning fixed paths)? AND Are all paths in that mapping hardcoded constants or loaded from a trusted source that is not controllable by the current user? AND Does the method use the retrieved path directly as the file location without subsequently concatenating any user-controlled strings?

Sample 2:

- **Whitelist Mapping to Safe Filename**: Does the method use a hardcoded mapping (e.g., a Map, array, or switch statement) that maps the user input to a predetermined file name or path component? AND Are all file name values in that mapping simple names that contain no path separators ('/' or '\\') and are not equal to '.' or '..'? AND Does the method use the mapped value as the complete final filename without further concatenation with any part of the user input?
- **java.io.File Canonical Path Prefix Check**: Does the method construct a java.io.File object using a fixed base directory and the user-provided path component? AND Is the base directory obtained from a constant or trusted source, not incorporating any part of the user input? AND Does the method call getCanonicalPath() on both the base directory File and the constructed File? AND Does the method verify that the constructed file's canonical path starts with the base directory's canonical path followed by the system file separator (i.e., baseCanonicalPath + File.separator)?
- **java.nio.file.Path Real Path Prefix Check**: Does the method use java.nio.file.Path.of() or Paths.get() to obtain the base directory path, and resolve the user input against it using resolve()? AND Is the base directory path defined using only hardcoded strings or trusted configuration, not incorporating any part of the user input? AND Does the method call toRealPath() on both the base directory Path and the resolved Path? AND Does the method use startsWith(baseRealPath) to verify that the real path of the constructed file is a descendant of the base directory's real path?
- **Last Component Extraction with Strict Validation**: Does the method use `new java.io.File(userInput).getName()` or `Path.of(userInput).getFileName()` to extract only the last path component (the simple file name) from the user input? AND Does the method validate that the extracted file name is not null, not empty, not equal to `.`, not equal to `..`, and does not contain any occurrence of '/' or '\\' characters? AND Does the method then combine this validated file name with a fixed base directory to construct the final path, without further incorporating the original user input?
- **java.nio.file.Path Normalize and Prefix Check**: Does the method use java.nio.file.Path to represent a fixed base directory, and resolve the user input against it using resolve()? AND Is the base directory path defined using only hardcoded strings or trusted configuration, not incorporating any part of the user input? AND Does the method call normalize() on the resulting path? AND Does the method check that the normalized path starts with the normalized base path by calling startsWith(basePath.normalize())?

Sample 3:

- **Canonical path check with startsWith**: Is there a base directory (field, constant, or local variable typed as java.io.File or java.nio.file.Path) representing the restricted parent? AND Does the method construct a target path from the base directory and the user input (e.g., new File(baseDir, userInput) or baseDir.resolve(userInput))? AND Does the method obtain the canonical path of the base directory using File.getCanonicalPath() or Path.toRealPath()? AND Does the method obtain the canonical path of the constructed target using File.getCanonicalPath() or Path.toRealPath()? AND Does the method verify that the canonical target path equals or is a proper descendant of the canonical base path (e.g., targetCanonicalPath.equals(baseCanonicalPath) || targetCanonicalPath.startsWith(baseCanonicalPath + File.separator))?
- **Whitelist mapping**: Does the method use a hardcoded mapping (e.g., Map, switch, if/else chain) from the user input to a fixed safe file path that does not contain any part of the input? AND Does the method reject the input or return a safe default when it does not match any mapping entry?
- **Sanitization with FilenameUtils.getName**: Does the method call org.apache.commons.io.FilenameUtils.getName() on the user input? AND Does the method construct the target path by combining a fixed base directory with the result of getName() (e.g., new File(baseDir, FilenameUtils.getName(input)))? AND Is the base directory assigned from a constant or field, not influenced by any user input?
- **Strict filename validation**: Does the method validate the user input by checking that it matches a regular expression that allows only alphanumeric characters, hyphens, underscores, and periods, and explicitly rejects characters like '/', '\', and the '..' sequence? AND Does the validation also reject input containing the null character ('\0')? AND Does the method construct the target path by combining a fixed base directory with the validated input (e.g., new File(baseDir, input))? AND Is the base directory assigned from a constant or field, not influenced by any user input?

## Calls

| Kind | Calls | Failed | Reported cost |
| --- | ---: | ---: | ---: |
| checklist | 3 | 0 | $0.0554 |
| checklist answer (Jev) | 43 | 0 | $0.0029 |
| hinted answer | 120 | 0 | $1.3836 |
| judge (Jev) | 221 | 0 | $0.0713 |

Failures, counted as kept locations:

- none
