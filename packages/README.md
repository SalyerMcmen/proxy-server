# Custom tarballs

Do not edit this directory by hand. Build a modified package with `npm pack`,
then register it from the repository root:

```bash
npm run register-package -- ../modified-package/package.tgz --tag company
```

The registration script copies the tarball here, calculates SHA-1 and SHA-512
integrity values, extracts its `package.json`, and updates
`config/custom-packages.json`.

Use a new version such as `1.2.3-company.1`. Replacing an existing name and
version breaks npm's immutability and cache assumptions, so it is rejected
unless `--replace` is explicitly supplied.
