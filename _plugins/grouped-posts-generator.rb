#!/usr/bin/env ruby
# frozen_string_literal: true

require 'date'
require 'safe_yaml'

module GroupedPosts
  DATE_SLUG_PATTERN = /\A(?<date>\d{4}-\d{2}-\d{2})-(?<slug>.+)\z/.freeze
  DEFAULT_POST_DATA = {
    'layout' => 'post',
    'comments' => true,
    'toc' => true,
    'permalink' => '/posts/:title/'
  }.freeze

  class CollectionPostDocument < Jekyll::Document
    attr_reader :grouped_source_path

    def initialize(virtual_path, grouped_source_path, site, collection)
      @grouped_source_path = grouped_source_path
      super(virtual_path, { site: site, collection: collection })
    end

    def read(_opts = {})
      raw = File.read(grouped_source_path)
      front_matter, body = split_front_matter(raw)

      @content = body
      @data = DEFAULT_POST_DATA.merge(front_matter)
      @data['date'] ||= parsed_date_from_basename
      @data['title'] ||= title_from_slug(collection_slug)
      @data['permalink'] = front_matter['permalink'] || "/posts/#{collection_slug}/"
      @data['grouped_post'] = true
      @data['grouped_source'] = grouped_source_path.sub(%r!\A#{Regexp.escape(site.source)}/?!, '')

      merge_data!(@data)
      self
    end

    private

    def split_front_matter(raw)
      return [{}, raw] unless raw.start_with?("---\n")

      parts = raw.split(/^---\s*$/, 3)
      return [{}, raw] unless parts.size >= 3

      data = SafeYAML.load(parts[1]) || {}
      [data, parts[2].sub(/\A\n/, '')]
    rescue StandardError => e
      Jekyll.logger.warn 'Grouped posts:', "Could not parse front matter in #{grouped_source_path}: #{e.message}"
      [{}, raw]
    end

    def parsed_date_from_basename
      match = DATE_SLUG_PATTERN.match(File.basename(path, '.md'))
      match ? Date.parse(match[:date]) : nil
    end

    def collection_slug
      match = DATE_SLUG_PATTERN.match(File.basename(path, '.md'))
      match ? match[:slug] : File.basename(path, '.md')
    end

    def title_from_slug(slug)
      slug.tr('_-', ' ').split.map(&:capitalize).join(' ')
    end
  end

  class Generator < Jekyll::Generator
    safe true
    priority :highest

    def generate(site)
      posts_dir = File.join(site.source, '_posts')
      collection = site.collections['posts']
      return unless collection && Dir.exist?(posts_dir)

      group_dirs(posts_dir).each do |group_dir|
        build_group(site, collection, group_dir)
      end

      collection.docs.sort_by! { |doc| doc.date || Time.at(0) }.reverse!
    end

    private

    def group_dirs(posts_dir)
      Dir.children(posts_dir)
         .map { |entry| File.join(posts_dir, entry) }
         .select { |path| File.directory?(path) && DATE_SLUG_PATTERN.match?(File.basename(path)) }
         .sort
    end

    def build_group(site, collection, group_dir)
      intro_path = File.join(group_dir, 'intro.md')
      subpost_dir = File.join(group_dir, 'post')
      return unless File.file?(intro_path)

      group_name = File.basename(group_dir)
      group_doc = collection_doc(site, collection, group_name, intro_path)
      return unless group_doc

      collection.docs << group_doc unless collection.docs.any? { |doc| doc.path == group_doc.path }

      subposts = discover_subposts(site, collection, subpost_dir)
      annotate_group_doc(group_doc, group_name, subposts, site)
      annotate_subposts(subposts, group_doc, group_name)
    end

    def collection_doc(site, collection, group_name, intro_path)
      virtual_path = File.join(site.source, '_posts', "#{group_name}.md")
      existing = collection.docs.find { |doc| doc.path == virtual_path }
      return existing if existing

      CollectionPostDocument.new(virtual_path, intro_path, site, collection).read
    rescue StandardError => e
      Jekyll.logger.warn 'Grouped posts:', "Could not create collection post #{group_name}: #{e.message}"
      nil
    end

    def discover_subposts(site, collection, subpost_dir)
      return [] unless Dir.exist?(subpost_dir)

      paths = Dir.glob(File.join(subpost_dir, '**', '*.md')).sort
      paths.filter_map do |path|
        collection.docs.find { |doc| doc.path == path } || create_subpost(site, collection, path)
      end
    end

    def create_subpost(site, collection, path)
      doc = Jekyll::Document.new(path, { site: site, collection: collection })
      doc.read
      collection.docs << doc
      doc
    rescue StandardError => e
      Jekyll.logger.warn 'Grouped posts:', "Could not create sub-post #{path}: #{e.message}"
      nil
    end

    def annotate_group_doc(group_doc, group_name, subposts, site)
      group_doc.data['grouped_post'] = true
      group_doc.data['collection_slug'] = slug_from_name(group_name)
      group_doc.data['collection_source'] = "_posts/#{group_name}"
      group_doc.data['subpost_count'] = subposts.size
      group_doc.data['subposts'] = subposts.each_with_index.map do |doc, index|
        subpost_card(doc, index, site)
      end
    end

    def annotate_subposts(subposts, group_doc, group_name)
      subposts.each_with_index do |doc, index|
        doc.data['grouped_subpost'] = true
        doc.data['collection_order'] ||= index + 1
        doc.data['parent_collection'] = {
          'title' => group_doc.data['title'],
          'url' => group_doc.url,
          'slug' => slug_from_name(group_name),
          'source' => "_posts/#{group_name}"
        }
      end
    end

    def subpost_card(doc, index, site)
      image = doc.data['image']
      image_path = image.is_a?(Hash) ? image['path'] : image

      {
        'title' => doc.data['title'] || title_from_doc(doc),
        'url' => doc.url,
        'date' => doc.date,
        'description' => doc.data['description'],
        'excerpt' => excerpt_for(doc),
        'categories' => doc.data['categories'] || [],
        'tags' => doc.data['tags'] || [],
        'image' => image_path,
        'image_alt' => image.is_a?(Hash) ? image['alt'] : nil,
        'media_subpath' => doc.data['media_subpath'],
        'order' => doc.data['collection_order'] || index + 1,
        'source' => doc.path.sub(%r!\A#{Regexp.escape(site.source)}/?!, '')
      }
    end

    def slug_from_name(group_name)
      match = DATE_SLUG_PATTERN.match(group_name)
      match ? match[:slug] : group_name
    end

    def title_from_doc(doc)
      title_from_slug(File.basename(doc.path, '.md').sub(/\A\d{4}-\d{2}-\d{2}-/, ''))
    end

    def title_from_slug(slug)
      slug.tr('_-', ' ').split.map(&:capitalize).join(' ')
    end

    def excerpt_for(doc)
      source = doc.data['description'] || doc.content.to_s
      source.gsub(/```.*?```/m, ' ')
            .gsub(/!\[[^\]]*\]\([^)]+\)/, ' ')
            .gsub(/\[[^\]]+\]\([^)]+\)/) { |match| match[/\[(.*?)\]/, 1] || match }
            .gsub(/[#>*_`~|-]/, ' ')
            .gsub(/\s+/, ' ')
            .strip
            .slice(0, 220)
    end
  end
end
