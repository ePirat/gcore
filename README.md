# gcore – A core dump utility for OS X
gcore is a core dump utility for OS X (named after similar tools) and was created
by Amit Singh and published along with his book [“Mac OS X Internals”][book-amazon] in the online
[bonus chapter][book-core].

## Usage

<pre><code><strong>gcore</strong> [-c <em>corefile</em>] [-s] &lt;pid&gt;</code></pre>


### Options
<dl>
    <dt>-c</dt>
    <dd>Specify the file where to store the dump<br />Default: <code>core.<em>PID</em></code></dd>
    <dt>-s</dt>
    <dd>Suspend the process while dumping it's memory.<br />
        <strong>Note:</strong> If the process was already suspended, it will be resumed nevertheless.</dd>
</dl>

[book-core]: http://www.osxbook.com/book/bonus/chapter8/core/
[book-amazon]: http://www.amazon.com/gp/product/0321278542/