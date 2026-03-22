# Neo-Virex Blog

This repository contains the Neo-Virex Jekyll blog, configured to build correctly for GitHub Pages and Vercel.

## Problems Before The Fixes

- GitHub Actions was using Ruby `3.1`, but the resolved gem set required a newer Ruby version, so `bundle install` failed during Pages builds.
- `Gemfile.lock` only had platform-specific entries and was missing the generic `ruby` platform, which caused Bundler platform warnings and dependency resolution issues in CI.
- The production Sass build failed because `_sass/main.bundle.scss` imports `vendors/bootstrap`, but `_sass/vendors/_bootstrap.scss` did not exist in the repository.
- GitHub Pages could deploy successfully and still look outdated because the PWA service worker was caching old content.
- Vercel was only running `npm run build`, which generated JavaScript assets but did not generate the Jekyll output directory `_site`, so deployments failed with the missing output directory error.

## What Was Fixed

- `.github/workflows/jekyll.yml`
  Changed the GitHub Actions Ruby version from `3.1` to `3.3`.

- `.ruby-version`
  Added `3.3.8` so local Ruby and CI Ruby match.

- `Gemfile.lock`
  Added the generic `ruby` platform and generic gem entries needed for CI, including `ffi`, `nokogiri`, and `sass-embedded`.

- `_sass/vendors/_bootstrap.scss`
  Added the generated Bootstrap vendor stylesheet required by the production Sass build.

- `_config.yml`
  Disabled `pwa.enabled` and `pwa.cache.enabled` so new GitHub Pages deployments are not hidden by stale cached content.

- `vercel.json`
  Added Vercel build settings so Vercel installs dependencies, runs the Jekyll build, and outputs to `_site`.

## Commands Used To Verify The Fixes

- `bundle install --jobs 4`
- `bundle exec jekyll build`
- `JEKYLL_ENV=production bundle exec jekyll build --baseurl ""`
- `npm run build && JEKYLL_ENV=production bundle exec jekyll build --baseurl ""`

## Current Vercel Note

- The repository contains `vercel.json`, but Vercel dashboard project settings can still override repository settings.
- If Vercel still runs only `npm run build`, then the dashboard settings need to be updated to match the repository configuration.
