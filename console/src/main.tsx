import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { DraftProvider } from "./draft.tsx";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <DraftProvider>
      <App />
    </DraftProvider>
  </StrictMode>,
);
