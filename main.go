package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/yeka/zip"
)

const START_YEAR = 2021
const END_YEAR = 2023
const BASE_URL = "https://www.malware-traffic-analysis.net"

func main() {
	for y := START_YEAR; y <= END_YEAR; y++ {

		sub_url, _ := url.JoinPath(BASE_URL, strconv.Itoa(y))

		resp, err := http.Get(sub_url)

		if err != nil {
			log.Fatal("[Base URL is not accessible]\n", err)
		}

		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)

		if err != nil {
			log.Fatal("[Failed to read a html document]\n", err)
		}

		sub_dir := filepath.Join("./res", strconv.Itoa(y))

		if _, err := os.Stat(sub_dir); os.IsNotExist(err) {
			// directory for a certain year does not exist
			if err := os.Mkdir(sub_dir, os.ModePerm); err != nil {
				log.Fatal(err)
			}
		}

		doc.Find("li .main_menu").Each(func(i int, s *goquery.Selection) {
			link, _ := s.Attr("href")

			if link == "../index.html" {
				return
			}

			re_index := regexp.MustCompile("([0-9a-zA-Z]+).html")
			link = re_index.ReplaceAllString(link, "")

			post_url, _ := url.JoinPath(sub_url, link)

			resp, err := http.Get(post_url)

			if err != nil {
				log.Fatal("[Post URL is not accessible]\n", err)
			}

			post_main, err := goquery.NewDocumentFromReader(resp.Body)

			if err != nil {
				log.Fatal("[Failed to read a html document]\n", err)
			}

			date := strings.Split(link, "/")
			article_name := strconv.Itoa(y) + "-" + date[0] + "-" + date[1] + "-" + s.Text()

			// file name can't include symbol ':', '>', '/', etc.
			re := strings.NewReplacer(
				":", "_",
				"<", "_",
				"|", "_",
				">", "_",
				"/", "_",
				"\\", "_",
				"*", "_",
				"?", "_",
				"\"", "_",
			)

			article_name = re.Replace(article_name)
			post_dir := filepath.Join(sub_dir, article_name)
			post_path := filepath.Join(post_dir, "index.html")

			if _, err := os.Stat(post_dir); os.IsNotExist(err) {
				// directory for a certain post entity does not exist
				if err := os.Mkdir(post_dir, os.ModePerm); err != nil {
					fmt.Println(err)
				}
			}

			err = DownloadFile(post_path, post_url, false)

			if err != nil {
				log.Fatal("[Download index.html failed]\n", err, post_path)
			}

			var file_idx = 0

			post_main.Find("li .menu_link").Each(func(i int, s *goquery.Selection) {
				res_link, _ := s.Attr("href")

				if !strings.HasSuffix(res_link, ".zip") {
					return
				}

				file_url, err := url.JoinPath(post_url, res_link)

				if err != nil {
					log.Fatal(err)
				}

				if strings.HasSuffix(res_link, ".pcap.zip") || strings.HasSuffix(res_link, ".pcaps.zip") { // packet data
					file_path := filepath.Join(post_dir, "packet"+strconv.Itoa(i)+".zip")
					fmt.Printf("--Packet : %s\n", res_link)
					err = DownloadFile(file_path, file_url, true)
				} else { // other materials
					file_idx += 1
					file_path := filepath.Join(post_dir, "associated files"+strconv.Itoa(file_idx)+".zip")
					fmt.Printf("--Others : %s\n", res_link)
					err = DownloadFile(file_path, file_url, false)
				}

				if err != nil {
					log.Fatal("[Download data source failed]\n", err)
				}
			})

			fmt.Printf("Reading posts in %d : %d (%s)\n", y, i, article_name)
		})
	}
}

// Download from a given url to a file.
func DownloadFile(path string, url string, extract bool) error {
	err := os.MkdirAll(filepath.Dir(path), 0770)

	if err != nil {
		return err
	}

	out, err := os.Create(path)

	if err != nil {
		return err
	}

	resp, err := http.Get(url)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)

	if err != nil {
		return err
	}

	defer out.Close()

	if extract {
		err = unzip(path)

		if err != nil {
			return err
		}

		defer os.Remove(path)
	}

	defer out.Close()

	return nil
}

// Unzip files with a secret password
func unzip(src string) error {
	r, err := zip.OpenReader(src)

	if err != nil {
		return err
	}

	defer r.Close()

	re := regexp.MustCompile("packet([0-9]+).zip")
	dest := re.ReplaceAllString(src, "packet")

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword("infected")
		}

		rc, err := f.Open()

		if err != nil {
			return err
		}

		defer rc.Close()

		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
		} else {
			var fdir string

			if lastIndex := strings.LastIndex(fpath, string(os.PathSeparator)); lastIndex > -1 {
				fdir = fpath[:lastIndex]
			}

			err = os.MkdirAll(fdir, f.Mode())

			if err != nil {
				return err
			}

			f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())

			if err != nil {
				return err
			}

			defer f.Close()

			_, err = io.Copy(f, rc)

			if err != nil {
				return err
			}
		}
	}

	return nil
}
