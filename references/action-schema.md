# Structured `computer_action` Schema

Model-agnostic JSON action protocol compatible with any vision or text-only AI model.

## Action Envelope

When operating inside an automated agent loop, emit **one** structured JSON block per step:

```computer_action
{
  "action": "open_app",
  "app": "calc",
  "reason": "Opening calculator to verify computation"
}
```

## Supported Actions (19)

| `action` | Parameters | Description |
|---|---|---|
| `capture_screen` | `windowTitle?`, `reason` | Captures primary screen or specific window to PNG (max width 1280px). |
| `inspect_windows` | `reason` | Lists visible top-level windows with process name, bounds, and active flag. |
| `read_ui_elements` | `windowTitle?`, `reason` | Reads accessible child UI controls and bounding rectangles. |
| `move_mouse` | `x`, `y`, `coordinateSpace?`, `reason` | Moves cursor to coordinates and verifies final position. |
| `click` | `x`, `y`, `button?` (`left\|right\|middle`), `clicks?` (`1\|2`), `coordinateSpace?`, `reason` | Clicks or double-clicks at resolved coordinates. |
| `drag` | `x`, `y`, `toX`, `toY`, `button?`, `coordinateSpace?`, `reason` | Multi-step smooth drag between two points. |
| `scroll` | `dx?`, `dy?`, `x?`, `y?`, `coordinateSpace?`, `reason` | Vertical (`dy`) and horizontal (`dx`) wheel scrolling. |
| `type_text` | `text`, `sensitive?`, `reason` | Sends UTF-16 Unicode keystrokes (max 500 chars per step). |
| `press_key` | `key`, `modifiers?` (`["ctrl","shift","alt","win"]`), `reason` | Sends single key or shortcut combination. |
| `open_app` | `app`, `url?`, `reason` | Launches a safe user application. |
| `manage_window` | `windowTitle`, `operation` (`focus\|minimize\|maximize\|restore\|close`), `reason` | Controls a matching window. |
| `navigate_url` | `url`, `browser?`, `reason` | Opens an `http://` or `https://` URL in the browser. |
| `inspect_web_page` | `url`, `reason` | Fetches a read-only SSRF-protected DOM summary (title, H1/H2, buttons, links). |
| `clipboard_read` | `reason` | Reads system clipboard text with automatic secret redaction. |
| `clipboard_write` | `text`, `reason` | Writes text to system clipboard. |
| `create_desktop_folder` | `path`, `reason` | Creates a folder strictly inside the user's Desktop. |
| `create_desktop_file` | `path`, `content`, `reason` | Writes a non-executable text file strictly inside the user's Desktop. |
| `wait` | `ms` (`100..5000`), `reason` | Waits for UI animation or page render. |
| `finish` | `summary`, `verifiedEvidence` | Completes the task with verified evidence. |

## Coordinate Space Resolution

- `physical`: Direct physical screen pixels `(x, y)`.
- `scaled` / `screenshot`: Coordinates measured on the downsampled screenshot image (`width x height`), automatically converted to physical screen coordinates using `(x * physicalWidth / scaledWidth, y * physicalHeight / scaledHeight)`.
- `normalized`: `0..1000` normalized grid mapped to `(0..physicalWidth-1, 0..physicalHeight-1)`.
