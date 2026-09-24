local TAB = utf8.char(0xE000)
local SPACE = utf8.char(0xE001)

local function asn1(block)
  return block.t == 'Div' and block.attributes['custom-style'] == 'ASN.1'
end

local function underline(el)
  local out = pandoc.List({ pandoc.Str('__') })
  out:extend(el.content)
  out:insert(pandoc.Str('__'))
  return out
end

local function header(el)
  local out = pandoc.List({ pandoc.Str(string.rep('#', el.level)), pandoc.Space() })
  out:extend(el.content)
  return pandoc.Para(out)
end

local function blocks(list)
  local out = pandoc.List()
  local run = nil
  for _, block in ipairs(list) do
    if asn1(block) then
      local inlines = pandoc.utils.blocks_to_inlines(block.content, { pandoc.LineBreak() })
      if run then
        run:insert(pandoc.LineBreak())
        run:extend(inlines)
      else
        run = pandoc.List(inlines)
      end
    else
      if run then
        out:insert(pandoc.Para(run))
        run = nil
      end
      out:insert(block)
    end
  end
  if run then
    out:insert(pandoc.Para(run))
  end
  return out
end

local input, output = arg[1], arg[2]
local source = io.open(input, 'rb')
local archive = pandoc.zip.Archive(source:read('a'))
source:close()

local entries = pandoc.List()
for _, entry in ipairs(archive.entries) do
  if entry.path == 'word/document.xml' then
    local xml = entry:contents()
      :gsub('(<w:t[^>]*>)([^<]*)(</w:t>)', function(open, text, close)
        return open .. text:gsub(' ', SPACE) .. close
      end)
      :gsub('<w:tab/>', '<w:t xml:space="preserve">' .. TAB .. '</w:t>')
    entries:insert(pandoc.zip.Entry(entry.path, xml))
  else
    entries:insert(entry)
  end
end

local document = pandoc.read(pandoc.zip.Archive(entries):bytestring(), 'docx+styles')
document = document:walk({ Underline = underline, Header = header })
document = document:walk({ Blocks = blocks })
local text = pandoc.write(document, 'plain', { wrap_text = 'wrap-none' }):gsub(TAB, '\t'):gsub(SPACE, ' ')

local target = io.open(output, 'wb')
target:write(text)
target:close()
