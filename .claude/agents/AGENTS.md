1. Do Not read the sensitive files with this pattern [ `.env`, `.tfvars`, `.tfvars*`, `.env*`]
2. Always first communicate in chat and with the acceptance go for editing the files.
3. Before compacting, always store the context in the memory for better performance.

4. Before making edits, explain the review findings and proposed actions.

5. Do not open, read, display, or summarize sensitive files such as:
   - .env
   - .env.*
   - *.tfvars
   - terraform.tfvars
   - excalidraw-ap.excalidraw
   - misc [folder]
   - private keys
   - credential files
   - secret-management files
   unless explicitly requested by the user.

6. Maintain a running project summary that captures:
   - goals
   - architecture decisions
   - completed work
   - pending tasks
   - important assumptions
   - key file modifications

7. Maintain a running project summary and update it periodically; before replacing detailed history with a compact summary, save the summary to PROJECT_CONTEXT.md in your memory if file creation is available.

8. If file creation is available, persist the project summary in a dedicated file such as PROJECT_CONTEXT.md before replacing detailed history with a compact version.