@import "_config"
@font-face
  font-family: 'Source Sans Pro'
  src: url('../fonts/SourceSansPro.ttf')

::selection
  background: color-primary
  color: color-white

body
  font-family: 'Source Sans Pro', 'Helvetica Neue', Arial, sans-serif
  -webkit-font-smoothing: antialiased
  -moz-osx-font-smoothing: grayscale
  -webkit-text-size-adjust: none
  position: relative
  height: 100%
  margin: 0
  color: color-dark
  font-size: 16px
  @media m-mobile
    font-size: 15px

ol, ul, form, p
  margin: 0

a
  text-decoration: none
  color: color-primary
  cursor: pointer

p
  word-spacing: 0.05em

pre
  overflow-x: auto

.flex-box
  display: flex
  display: -ms-flexbox
  display: -webkit-box
  display: -webkit-flex
  transform: unset !important

.wechat-share
  width: 0
  height: 0
  overflow: hidden
  img
    width: 400px
    height 400px

.app-body
  padding: 2em 1em
  margin: 0 auto
  height: 100%
  max-width: 980px
  position: relative
  opacity: 0
  transform: translateY(-20px)
  transition: all 0.4s

.hljs
  background: none !important

.tags
  margin: 15px 0
  span
    &:first-child
      margin-right: 10px
      font-weight: 600

.tag-code
  font-family: 'Roboto Mono', Monaco, courier, monospace
  font-size: .8em
  display: inline-block
  background-color: color-background
  color: color-orange
  padding: 3px 5px
  margin: 0 2px 5px 0
  border-radius: 2px
  white-space: nowrap

.article-card
  padding-bottom: 20px
  &:first-child
    margin-top: 60px

h2.article-head
  font-size: 1.6em
  margin-bottom: 0

.article-head > a
  color: color-dark
  &:hover
    border-bottom: 2px solid color-primary

.article-date
  color: color-gray
  margin: 10px 0
  font-size: 0.9em

.article-summary
  margin: 10px 0
  color: color-dark

.more
  font-weight: 600
  display: inline-block
  transition: all 0.3s
  &:hover
    transform: translateX(10px)

#article-banner
  width: 100%
  box-sizing: border-box
  top: 0
  left: 0
  padding: 100px 20px 25px 20px
  text-align: center
  position: relative
  background-repeat: no-repeat
  background-position: center
  background-size: cover
  @media m-mobile
    padding: 80px 10px 25px 10px
  h2
    margin: .4em 0
    font-size: 2.2em
    color: color-white
    text-shadow: 0 0 40px color-dark
    opacity: 0
    transform: translateY(-20px)
    transition: all 0.4s
    @media m-mobile
      font-size: 2em
  .post-date
    margin: 10px 0 20px 0
    color: color-white
    opacity: 0
    transform: translateY(-20px)
    transition: all 0.4s
    transition-delay: 0.05s
  .arrow-down
    display: flex
    width: 100%
    justify-content: center
    opacity: 0
    transform: translateY(-20px)
    transition: all 0.4s
    transition-delay: 0.1s
    a
      z-index: 4
      display: block
      width: 25px
      height: 25px
      -webkit-transform: rotate(315deg)
      transform: rotate(315deg)
      -webkit-animation-name: shine
      -webkit-animation-duration: 1.5s
      -webkit-animation-iteration-count: infinite
      animation-iteration-count: infinite
      border-bottom: 1px solid color-white
      border-left: 1px solid color-white

.post-article
  margin-top: 0
  width: 100%

.money-like
  padding: 2em 0 3em
  .reward-btn
    cursor: pointer
    font-size: 1.6em
    line-height: 2em
    position: relative
    display: block
    width: 2em
    height: 2em
    margin: 0 auto
    padding: 0
    text-align: center
    vertical-align: middle
    color: color-white
    border: 1px solid #f1b60e
    border-radius: 50%
    background: linear-gradient(to bottom, #fccd60 0, #fbae12 100%, #2989d8 100%, #207cca 100%)
  .money-code
    position: absolute
    top: -7em
    left: 50%
    display: none
    width: 10.5em
    height: 5.5em
    margin-left: -5.9em
    padding: 10px 15px
    background: color-white
    box-shadow: 0 0 0 1px color-border
    border-radius: 4px
    span
      display: inline-block
      width: 4.5em
      height: 4.5em
    .alipay-code
      float: left
      .code-image
        background-image: url(alipay-url)
        background-size: contain
        background-repeat: no-repeat
        width: 4.5em
        height: 4.5em
    .wechat-code
      float: right
      .code-image
        background-image: url(wechat-url)
        background-size: contain
        background-repeat: no-repeat
        width: 4.5em
        height: 4.5em
    b
      font-size: .5em
      line-height: 24px
      display: block
      margin: 0
      text-align: center
      color: color-dark

.notice
  font-size: 12px
  display: block
  margin-top: 10px
  text-align: center
  color: color-gray
  font-style: italic

.qrcode
  padding-bottom: 30px
  text-align: center
  border-bottom: 1px dashed color-border
  canvas
    width: 8em
    height: 8em
    padding: 5px
    box-shadow: 0 0 1px color-shadow

#uyan_frame
  margin-top: 20px

.image-view-wrap
  position: fixed
  top: 0
  left: 0
  bottom: 0
  right: 0
  z-index: 1000
  transition: all 0.3s ease-in-out
  .image-view-inner
    position: relative
  img
    display: block
    margin: 0 auto
    cursor: zoom-out
    transition: all 0.3s ease-in-out
.wrap-active
  background-color: rgba(255, 255, 255, .9)

.scroll-top
  cursor: pointer
  opacity: 0
  position: fixed
  box-sizing: border-box
  right: 2em
  bottom: 45px
  width: 40px
  height: 40px
  padding: 5px
  background-color: color-primary
  border-radius: 20px
  transform: translate(80px, 0)
  transition: all .3s ease
  box-shadow: 0 0 3px 0 rgba(0,0,0,.12), 0 3px 3px 0 rgba(0,0,0,.24)
  .arrow-icon
    background-image: url(arrow-url)
    width: 30px
    height: 30px
    display: block
    background-size: contain

.opacity
  opacity: 1
  transform: translate(0, 0)

@keyframes shine
  0%, 100%
    opacity: .1
  25%, 75%
    opacity: .2
  50%
    opacity: 1

@import "_partial/header"
@import "_partial/footer"
@import "_partial/pager"
@import "_partial/markdown"
@import "_partial/tags"
@import "_partial/archive"
@import "_partial/about"
@import "_partial/project"
@import "_partial/catalog"
@import "_partial/nav"
