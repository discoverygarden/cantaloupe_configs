require '/opt/cantaloupe_configs/delegates.rb'
require 'base64'
require 'net/http'
require 'cache_lib'

# We build up a tree of cache buckets, in order, per:
# - site: A bucket for each site we're aware of...
#   - token: A bucket for each token we see... hypothetically, tokens could be
#            used over a longer lifespan... and it would probably be a good idea
#            to do so... especially with the anonymous-user-degenerate-case,
#            the don't have a token to pass so we can track all their stuff
#            together.
#     - resource: A bucket for each resource, checked with the given token on
#                 the given site.
$sites_cache = CacheLib.create :lru, $info['sitemap'].length

class CustomDelegate
  old_function = instance_method(:httpsource_resource_info)

  # Get the resource suffix for the given ID.
  def _suffix
    values = CGI::unescape(context['identifier']).split('~')
    if values.length == 2
      suffix, site_id = values
      return suffix
    end
  end

  # Get the site identifier portion of the ID.
  def _site_id
    values = CGI::unescape(context['identifier']).split('~')
    if values.length == 2
      suffix, site_id = values
      return site_id
    end
  end

  # Build up the full URL to the resource.
  def _resource
    if _site_id and _suffix
      $info['sitemap'].fetch(_site_id) % {
        suffix: Base64.decode64(_suffix),
      }
    end
  end

  # Override; allow the passing of additional headers for auth.
  def httpsource_resource_info(options = {})
    if _site_id
      url = _resource

      $logger.debug("Site ID '#{_site_id}' resolved to '#{url}'.")

      to_return = { "uri" => url }

      to_return['headers'] = _headers

      return to_return
    else
      return old_function.bind(self).call
    end
  end

  # The name of our header.
  def _header
    # XXX: Downcase'd as, Cantaloupe normalizes them to be such.
    'X-DGI-I8-Helper-Authorization-Token'.downcase
  end

  # Fetch the value of our passed header.
  #
  # Returns the empty string if the header was _not_ passed.
  def _header_value
    if context['request_headers'].has_key?(_header)
      context['request_headers'][_header]
    else
      ''
    end
  end

  # Retrieve a hash of headers to pass.
  def _headers
    to_return = Hash.new

    if context['request_headers'].has_key?(_header)
      to_return['Authorization'] = "Bearer #{_header_value}"
    end

    return to_return
  end

  # Fetch the URL using the HEAD method.
  #
  # Adapted from https://stackoverflow.com/a/6934503
  def _fetch(uri, limit = 10)
    # StandardError should suffice.
    raise 'HTTP redirect too deep' if limit == 0

    head = Net::HTTP::Head.new uri
    _headers.each do |header, value|
      head[header] = value
    end

    # XXX: Ideally, we could use some form of connection pooling or
    # something here.
    Net::HTTP.start head.uri.host, head.uri.port, :use_ssl => uri.is_a?(URI::HTTPS) do |http|
      resp = http.request head
      $logger.debug("Response: #{resp}")

      case resp
      when Net::HTTPSuccess     then resp
      when Net::HTTPRedirection then _fetch(URI(resp['location']), limit - 1)
      else
        resp.error!
      end
    end
  end

  # Override; handle I8 resource auth.
  def authorize(options = {})
    # If...
    if _resource
      # ... we have something that appears to be an I8 resource, enforce auth...
      $sites_cache.limit = $info['sitemap'].length
      site_cache = $sites_cache.get(_site_id) {
        $logger.debug("Creating token bucket for #{_site_id}")
        # XXX: Implicit return to populate cache value.
        CacheLib.create :ttl, 1024, 600
      }
      site_token_cache = site_cache.get(_header_value) {
        # XXX: Want to check the token before the resource, because we could
        # fall into the base "anonymous" case, without the header (using the
        # empty string as the token).
        $logger.debug("Creating resource bucket a token in #{_site_id}.")
        # XXX: Implicit return to populate cache value.
        CacheLib.create :ttl, 100, 60
      }
      begin
        return site_token_cache.get(_resource) {
          # XXX: Implicit return to populate cache value.
          _fetch(URI(_resource)).is_a?(Net::HTTPSuccess)
        }
      rescue => e
        $logger.error("Exception: #{e}")
        return false
      end
    else
      # ... otherwise, pass it, assuming it should contain an auth token in the
      # URL.
      return true
    end
  end

end
