using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace WebBrowser.Engine;

public class HtmlRenderer
{
    public static FrameworkElement RenderHtml(string html, string baseUrl = "")
    {
        var container = new RichTextBox
        {
            IsReadOnly = true,
            Background = new SolidColorBrush(Colors.White),
            Foreground = new SolidColorBrush(Colors.Black),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 13,
            Padding = new Thickness(10),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        try
        {
            var doc = new HtmlAgilityPack.HtmlDocument();
            doc.LoadHtml(html);

            var paragraph = new Paragraph();
            RenderNode(doc.DocumentNode, paragraph, new RenderContext());
            container.Document.Blocks.Clear();
            container.Document.Blocks.Add(paragraph);
        }
        catch (Exception ex)
        {
            container.Document.Blocks.Clear();
            container.Document.Blocks.Add(new Paragraph(new Run($"Error rendering page: {ex.Message}")));
        }

        return container;
    }

    private static void RenderNode(HtmlAgilityPack.HtmlNode node, Block parent, RenderContext context)
    {
        if (node.NodeType == HtmlAgilityPack.HtmlNodeType.Text)
        {
            var text = HtmlAgilityPack.HtmlEntity.DeEntitize(node.InnerText);
            if (!string.IsNullOrWhiteSpace(text))
            {
                var run = new Run(text) { Foreground = new SolidColorBrush(context.TextColor) };
                if (context.IsBold) run.FontWeight = FontWeights.Bold;
                if (context.IsItalic) run.FontStyle = FontStyles.Italic;

                if (parent is Paragraph para)
                    para.Inlines.Add(run);
            }
            return;
        }

        var tagName = node.Name.ToLower();

        switch (tagName)
        {
            case "h1":
            case "h2":
            case "h3":
                var heading = new Paragraph { FontSize = GetHeadingSize(tagName), FontWeight = FontWeights.Bold };
                foreach (var child in node.ChildNodes)
                    RenderNode(child, heading, context);
                if (parent is Paragraph p) p.Inlines.Add(heading);
                break;

            case "b":
            case "strong":
                context.IsBold = true;
                foreach (var child in node.ChildNodes)
                    RenderNode(child, parent, context);
                context.IsBold = false;
                break;

            case "i":
            case "em":
                context.IsItalic = true;
                foreach (var child in node.ChildNodes)
                    RenderNode(child, parent, context);
                context.IsItalic = false;
                break;

            case "a":
                var href = node.GetAttributeValue("href", "#");
                var linkContext = context with { TextColor = Colors.Blue };
                context.IsBold = true;
                foreach (var child in node.ChildNodes)
                    RenderNode(child, parent, linkContext);
                context.IsBold = false;
                break;

            case "br":
                if (parent is Paragraph para2)
                    para2.Inlines.Add(new LineBreak());
                break;

            case "p":
                var paragraph = new Paragraph();
                foreach (var child in node.ChildNodes)
                    RenderNode(child, paragraph, context);
                if (parent is Paragraph parentPara)
                    parentPara.Inlines.Add(paragraph);
                break;

            case "div":
            case "section":
            case "article":
                foreach (var child in node.ChildNodes)
                    RenderNode(child, parent, context);
                break;

            case "ul":
            case "ol":
                var list = new List { MarkerStyle = tagName == "ol" ? TextMarkerStyle.Decimal : TextMarkerStyle.Disc };
                foreach (var child in node.ChildNodes)
                {
                    if (child.Name.ToLower() == "li")
                    {
                        var item = new ListItem();
                        var itemPara = new Paragraph();
                        foreach (var subchild in child.ChildNodes)
                            RenderNode(subchild, itemPara, context);
                        item.Blocks.Add(itemPara);
                        list.ListItems.Add(item);
                    }
                }
                if (parent is Paragraph parentWithList)
                    parentWithList.Inlines.Add(list);
                break;

            default:
                foreach (var child in node.ChildNodes)
                    RenderNode(child, parent, context);
                break;
        }
    }

    private static double GetHeadingSize(string tag) => tag switch
    {
        "h1" => 28,
        "h2" => 24,
        "h3" => 20,
        _ => 16
    };

    private record RenderContext
    {
        public bool IsBold { get; set; }
        public bool IsItalic { get; set; }
        public Color TextColor { get; set; } = Colors.Black;
    }
}
