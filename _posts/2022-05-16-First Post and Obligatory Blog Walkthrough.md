---
title: First Post and Obligatory Blog Walkthrough
date: 2022-05-16 21:15:00 -0600
categories: [Meta, Walkthrough]
tags: [blog, tutorial, walkthrough]     # TAG names should always be lowercase
---

After much deliberation, I have finally settled on a way to host my thoughts, research, and walkthroughs on the internet. 

My indecision about the best way forward delayed this project for years (I've got some catching up to do), but I think I've found a solution that is relatively low cost and, more importantly, low maintenance. As with any good first blog post, I'm obligated to outline the process to set up a site like this.

> Although this blog's intent is for cybersecurity and offensive security research, tools, and guides, this particular how-to is intended for a wider audience; I am writing it in such a way that I hope anyone with an interested in an online blog can follow. However, with this method, one should be familiar with markdown (`.md`). 
{: .prompt-tip }

## Overview

To get our site up and running, we need to follow this basic framework:

1. Set up a github.com account.
2. Select a Jekyll Theme that suits our interest and intent.
3. Fork the GitHub repository of our chosen theme.
4. Clone repository.
5. Make a few config adjustments and create a post.
6. Publish to GitHub.
7. Enjoy the new site! 

## GitHub

GitHub allows free site hosting with their feature called [GitHub Pages](https://pages.github.com/). Simple creating an account on the site will grant us access to this. Pretty straightforward, only significant note here is that if you plan to use the free (default) domain, I'd suggest choosing a username that you don't mind being in the URL. 

## Jekyll

Next, let's get set up with Jekyll.

Jekyll is a great static site generator that supports a ton of different themes. When we fork a theme to our own repository, it usually includes all the necessary components to use or install jekyll out of the box. Convenient. 

There are a few places to find themes, like [here](http://jekyllthemes.org/) and [here](https://github.com/topics/jekyll-theme). Let's go pick one that suits or purpose and return when we're done. 

Once we've found our perfect theme, let's fork it to our repository. Now, to utilize GitHub pages, we need to name our new repository `<GITHUB-USERNAME>.github.io`, replacing the variable with the GitHub account username. This can be found in our repository, under settings.

Now that we've got a repository on GitHub for our blog, let's clone it to a local computer to enable editing and create our first post. Personally, I'm a big fan of using VS Code to manage my repositories. The package can be downloaded [here](https://code.visualstudio.com/download). Once installed, we can simply grab the `.git` link and clone our repository using VS Code, under source control.

![Clone Repo](/assets/img/posts/05-2022/clone.png)
_The location of the .git link on the repository._

## Configuration

> Any Operating System should be suitable to clone our repository, but this walkthrough will be accomplished with Linux in mind.
{: .prompt-tip }

Most themes will have instructions for configuring your site for first use, so let's just touch on a few general configurations that most Jekyll themes require. Once we have the cloned repository on our computer using VS Code, it should have opened up the repository. 

Once here, you'll see a quite a few directories and files. The `_config.yml` needs a few edits, at a minimum, to get the site configured correctly. This is usually were we can make the site our own. 

First thing, we'll change the title to whatever we want the website to be called. We can also change the sub-headings, description, or whatever else our theme allows us to modify. Some themes also give us the opportunity to add our social links, if we're into that. 

Take the time to go through the `_config.yml` file for any settings unique to your chosen theme. Once set, we can save the file.

Some other useful files and directories are:

- `_posts`: This is where our actual blogs posts will live.
- `_assets`: Images and the like go here.

Don't be afraid to look around to see what's going on. If you're interested in seeing how others have utilized your chosen theme, check out the other forks on GitHub.

## Preview

Once we've made our changes, let's preview our sight. When we run the following command in the terminal, a local instance of our sight will be available for our viewing pleasure.

```console
$ bundle exec jekyll s
```
{: .nolineno }

If no errors, our site can be accessed at `http://127.0.0.1:4000/`.

## First Post

Great! Our blog is "up" (at least locally) and appears to be usable. If we notice anything weird we can make changes on the fly and the site will update automatically. However, if it's `_config.yml` changes, we'll need stop the local instance with **ctrl+c** and re-run the above command. 

Ok, so the easy part is out of the way. Now, we've got to decide on and create our first post (This post is getting meta). 

Once we've settled, we'll create a markdown file in the `_posts` directory, and name it **yyyy-mm-dd-Title.md**, replacing the date with the actual date and **Title** with our decided title. From here, our chosen theme should provide some more details on what is needed for our post, usually found in the theme's README.

Let's go ahead and create our first post. Remember to use markdown to format it nicely and check the local preview to make sure everything jives.

## Publishing

Once finished, the site (and our first post) is ready to be published. We can stop the site preview with **ctrl+c** in the terminal, save what we're working on in VS Code with **ctrl+s**, and commit our changes.

![Commit changes](/assets/img/posts/05-2022/commit.png)
_Committing the changes._

To do so, we'll click source control on the VS Code sidebar, enter our commit message (something like, "first post!"), and hit **ctrl+Enter**. This will commit our changes locally. To push it back to GitHub and essentially publish our site, we will click *push* in the bottom left corner of VS Code. If a warning pops up, just hit okay. 

At last, our work has been pushed back to our GitHub repository. If we go to `<GITHUB-USERNAME>.github.io`, we should see our new site and our new post.

## Closing Thoughts

Now that the heavy lifting is out of the way, anytime we want to create a new post, all we need to do is create a new file in the `_posts` directory. Once we're done, we commit it and push to GitHub. Additionally, Jekyll supports quick file generation and publishing with the [jekyll-compose](https://github.com/jekyll/jekyll-compose) plug-in. 

It's also important to note, if you're interested in or already own a custom domain, GitHub pages easily supports this configuration. There are more [in-depth guides available](https://hackernoon.com/how-to-set-up-godaddy-domain-with-github-pages-a9300366c7b), but essentially all we need to do is add our custom domain to our repository's settings, then add GitHub's IP addresses to our DNS's A record and our original `<GITHUB-USERNAME>.github.io` to the DNS CNAME. All of which are easily configurable on a site like GoDaddy. 

This concludes my first post. I hope that it helps someone. I look forward to digging into infosec going forward.