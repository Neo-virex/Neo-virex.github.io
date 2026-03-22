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

## Adding A New Post

- Create the Markdown file in `_posts/`.
- Use the filename format `YYYY-MM-DD-slug.md`.
- The filename date controls the publish date.
- The filename slug controls the final post URL because the site permalink is `/posts/:title/`.

Example:

```text
_posts/2025-04-28-tryhackme_mayhem.md
```

This builds to:

```text
/posts/tryhackme_mayhem/
```

### Image Folder Rule

- Store post images in the top-level `images/` directory, not `assets/img`.
- Match the image folder to the post slug.
- Keep the folder name, `media_subpath`, and post slug consistent.

Examples:

```text
images/tryhackme/tryhackme_mayhem/
images/hackthebox/hackthebox_imagery/
images/blogs/hacking_tools/
```

### New Post Checklist

1. Pick the publish date.
2. Pick a lowercase slug.
3. Create the file as `YYYY-MM-DD-slug.md`.
4. Create the matching image folder under `images/`.
5. Put the cover image and all screenshots in that folder.
6. Add the front matter at the top of the Markdown file.
7. Set `media_subpath` to the matching image folder.
8. Set `image.path` to the exact cover image filename.
9. In the post body, reference images by filename only, such as `(img1.png)`.
10. Add the optional style block at the bottom if you use the `center` or `wrap` helper classes.

### Front Matter Template

```yaml
---
title: "TryHackme: Mayhem"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_mayhem/
image:
  path: room-img.png
description: "The Billing room on TryHackMe teaches you how to exploit a vulnerable billing system using basic web hacking techniques."
---
```

### Body Image Example

Because `media_subpath` is set, you can use image filenames directly inside the post body:

```md
![screenshot](img1.png)
![diagram](img2.webp)
```

### Optional Style Block

Put this at the bottom of the post if you want centered images or wrapped preformatted text:

```html
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
```

### Important Notes

- `render_with_liquid: false` prevents Jekyll/Liquid from breaking pasted code or note syntax.
- `image.path` must match the real cover image filename exactly.
- The common cover image names in this repo are `room-img.png`, `room_img.png`, and `room-img.jpeg`, so check the exact filename before committing.
