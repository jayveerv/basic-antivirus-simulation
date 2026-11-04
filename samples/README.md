# Samples

Test files are generated at run time so this repository is never flagged by your own antivirus:

```
python scan.py samples demo_files
```

| File | What it is | Expected verdict |
|---|---|---|
| eicar_test_file.com | EICAR antivirus test file (not malware) | Malicious |
| clean_notes.txt | Ordinary text | Clean |
| logo.png | Small valid image | Clean |
| suspicious_script.txt | Harmless text that looks like a PowerShell download script | Suspicious |
| ransom_note_sample.txt | Harmless text that looks like a ransom note | Suspicious |
| fake_packed_program.bin | Non-runnable file shaped like a packed injector | Malicious |
| random_data.bin | Random bytes (high entropy only) | Clean |
| invoice.pdf.exe | Plain text with a double extension | Suspicious |

Your own antivirus may react to the EICAR file. That is expected: it is the standard test file.
